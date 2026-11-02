"""The evidence sink: sign synchronously, persist asynchronously, chain always.

Shape of the thing:

* The LiteLLM hook signs (receipt construction + content addressing happen
  inline, on the request path) and does a *synchronous, non-blocking*
  enqueue. The request path never waits on disk.
* A single background flusher task owns the files. It collects receipts for
  up to ``flush_interval_s`` seconds or ``batch_size`` receipts, whichever
  comes first, then appends them to ``receipts.jsonl`` as hash-chained
  entries (:func:`szl_receipts.append` semantics: ``seq``, ``prev``,
  ``entry_digest``). Each batch rewrites the ledger crash-atomically: the
  full new contents go to a temp file in the same directory, which is
  fsynced and then renamed over ``receipts.jsonl``. One writer means no
  interleaving and no sequence races; the atomic rename means a crash
  mid-batch leaves the previous ledger, never a truncated or torn one.
* On restart the sink re-reads ``receipts.jsonl`` and offers it to
  :func:`szl_receipts.verify_chain`. **A corrupt on-disk chain refuses to
  boot** — continuing to append onto a tampered tail would manufacture
  false confidence. ``read_only=True`` opens the sink for inspection
  (``stats``, ``iterate``) without booting a flusher; verification that only
  reads should use :func:`verify_sink`, which needs no event loop at all.

Backpressure: when the bounded queue is full, FAIL_CLOSED raises
:class:`EvidenceBackpressure` (the caller's request fails loudly, per
policy) and FAIL_OPEN drops the receipt and increments ``dropped_counter``.
A dropped receipt is a *loud* signal: it is counted, surfaced in
:meth:`EvidenceSink.stats`, and one loud line is appended for the first drop
of each drop-streak. Silent loss is the one thing an evidence plane may
never do.

Files in the sink directory:

* ``receipts.jsonl`` — one chain entry per line (append-only chain, replaced atomically)
* ``evidence/<digest>.json`` — content-addressed evidence documents
* ``bodies/<digest>.json`` — captured bodies, only when capture is enabled
* ``chain_head.json`` — checkpoint {seq, entry_digest, entries} after each batch
* ``drops.jsonl`` — one line per drop-streak, only when FAIL_OPEN drops occur
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import os
import queue as thread_queue
import re
import secrets
import stat
import threading
import time
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from szl_receipts import append as chain_append
from szl_receipts import JcsError, jcs_canon_bytes, sha256_hex, verify_chain

from .modes import EvidencePolicy, FailMode

__all__ = [
    "CHAIN_HEAD_FILE",
    "CHAIN_LOG_FILE",
    "DROPS_LOG_FILE",
    "EvidenceBackpressure",
    "EvidenceSink",
    "PendingReceipt",
    "SinkBootError",
    "verify_sink",
]

CHAIN_LOG_FILE = "receipts.jsonl"
CHAIN_HEAD_FILE = "chain_head.json"
DROPS_LOG_FILE = "drops.jsonl"

#: Default bound on in-flight receipts. At ~2 KB per chained entry this is
#: ~20 MB of queued evidence — enough to absorb a flusher stall, small enough
#: that a wedged sink cannot eat the process.
DEFAULT_QUEUE_MAXSIZE = 10_000

_POSIX = os.name == "posix"
#: Directory fsync errors that mean "this filesystem cannot do that" rather
#: than "the disk failed". Only these are tolerated after the rename.
_DIR_FSYNC_UNSUPPORTED = frozenset(
    code
    for code in (
        getattr(errno, "EINVAL", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if code is not None
)
#: Windows refuses ``os.replace`` onto a file another handle has open (Python
#: opens files without FILE_SHARE_DELETE), e.g. a concurrent ``stats()`` or
#: ``verify_sink`` read. Those reads are short, so retry for about a second.
_REPLACE_RETRIES = 50 if os.name == "nt" else 0
_REPLACE_RETRY_DELAY_S = 0.02


@dataclass(frozen=True)
class PendingReceipt:
    """One receipt awaiting chain persistence, with its evidence sidecar."""

    receipt: dict[str, Any]
    evidence_doc: dict[str, Any]
    evidence_uri: str


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _evidence_path(base: Path, uri: Any, digest: Any) -> Path:
    """Admit only the sink's content-addressed, regular sidecar files.

    The sink directory is trusted. This rejects existing symlinks and special
    files; it does not make concurrent hostile filesystem replacement safe.
    """
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("invalid sidecar digest")
    if uri != f"evidence/{digest}.json":
        raise ValueError("sidecar URI is not its content-addressed path")
    target = base / uri
    if target.parent.is_symlink():
        raise ValueError("sidecar directory must not be a symlink")
    try:
        mode = target.lstat().st_mode
    except FileNotFoundError:
        return target
    if not stat.S_ISREG(mode):
        raise ValueError("sidecar must be a regular file, not a symlink or special file")
    return target


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate sidecar JSON key")
        result[key] = value
    return result


class EvidenceBackpressure(Exception):
    """Raised synchronously when the queue is full under a FAIL_CLOSED policy.

    This is the audit-grade posture doing its job: the request is refused
    rather than allowed to escape the evidence trail.
    """


class SinkBootError(Exception):
    """Raised when the on-disk chain fails verification at startup."""


class EvidenceSink:
    """Bounded-queue, batch-flushing, hash-chained receipt sink."""

    def __init__(
        self,
        directory: str | Path,
        *,
        policy: EvidencePolicy | None = None,
        maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        batch_size: int = 64,
        flush_interval_s: float = 0.5,
        read_only: bool = False,
    ) -> None:
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if flush_interval_s <= 0:
            raise ValueError("flush_interval_s must be > 0")
        self.directory = Path(directory)
        self.log_path = self.directory / CHAIN_LOG_FILE
        self.checkpoint_path = self.directory / CHAIN_HEAD_FILE
        self.drops_path = self.directory / DROPS_LOG_FILE
        self.policy = policy or EvidencePolicy.from_env()
        self.maxsize = maxsize
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.read_only = read_only

        self._dropped = 0
        self._dropped_open_streak = False
        self._queue: asyncio.Queue[PendingReceipt] | None = None
        self._queue_loop: asyncio.AbstractEventLoop | None = None
        self._flusher: asyncio.Task[None] | None = None
        # Completion belongs to the writer, not an event loop. A timed-out
        # close can be retried even after its original loop has been closed.
        self._inflight: Future[int] | None = None
        self._writer_executor: ThreadPoolExecutor | None = None
        # No-running-loop path: LiteLLM's sync callbacks can fire on executor
        # threads. A stdlib queue + daemon worker thread keeps enqueue()
        # synchronous and exact there; both paths converge on _persist_batch
        # under _persist_lock, so the chain file has exactly one writer at a
        # time regardless of which lane a receipt arrived on.
        self._tqueue: thread_queue.Queue[PendingReceipt] | None = None
        self._worker: threading.Thread | None = None
        self._worker_failure: Exception | None = None
        self._worker_stop = threading.Event()
        self._persist_lock = threading.Lock()

        if not read_only:
            self.directory.mkdir(parents=True, exist_ok=True)
            # The boot gate: never append onto a chain we cannot authenticate.
            report = verify_chain(self._read_jsonl(self.log_path))
            if not report.ok:
                raise SinkBootError(
                    f"refusing to extend a broken chain at {self.log_path}: "
                    + "; ".join(f["message"] for f in report.findings)
                )

    # ------------------------------------------------------------------ queue

    def enqueue(self, pending: PendingReceipt) -> None:
        """Synchronously queue a signed receipt for persistence. Never blocks.

        FAIL_CLOSED + full queue → :class:`EvidenceBackpressure`.
        FAIL_OPEN   + full queue → drop, count it, and log it loudly once
        per drop-streak. Both outcomes are explicit; there is no third.
        """
        self._check_worker_failure()
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            self._enqueue_thread(pending)
            return
        queue = self._require_queue()
        try:
            queue.put_nowait(pending)
        except asyncio.QueueFull:
            if self.policy.fail_mode is FailMode.FAIL_CLOSED:
                raise EvidenceBackpressure(
                    f"evidence queue full ({self.maxsize}); FAIL_CLOSED refuses "
                    "to let this call escape the evidence trail"
                ) from None
            self._dropped += 1
            if not self._dropped_open_streak:
                self._dropped_open_streak = True
                self._record_drop_streak()
        else:
            # A successful enqueue ends any open drop-streak, so a *later*
            # full queue triggers a fresh loud record rather than vanishing
            # into the previous one.
            self._dropped_open_streak = False

    def _enqueue_thread(self, pending: PendingReceipt) -> None:
        """Enqueue from a thread without a running loop (sync callbacks)."""
        if self.read_only:
            raise RuntimeError("read-only sinks inspect; they do not accept receipts")
        if self._tqueue is None:
            self._tqueue = thread_queue.Queue(maxsize=self.maxsize)
        try:
            self._tqueue.put_nowait(pending)
        except thread_queue.Full:
            if self.policy.fail_mode is FailMode.FAIL_CLOSED:
                raise EvidenceBackpressure(
                    f"evidence queue full ({self.maxsize}); FAIL_CLOSED refuses "
                    "to let this call escape the evidence trail"
                ) from None
            self._dropped += 1
            if not self._dropped_open_streak:
                self._dropped_open_streak = True
                self._record_drop_streak()
            return
        self._dropped_open_streak = False
        if self._worker is None or not self._worker.is_alive():
            self._worker_stop.clear()
            self._worker = threading.Thread(
                target=self._worker_loop,
                name=f"szl-evidence-worker:{self.directory}",
                daemon=True,
            )
            self._worker.start()

    def _worker_loop(self) -> None:
        """Batch-draining worker for the no-event-loop lane."""
        assert self._tqueue is not None  # noqa: S101 — set before thread start
        while not self._worker_stop.is_set():
            try:
                first = self._tqueue.get(timeout=self.flush_interval_s)
            except thread_queue.Empty:
                continue
            batch = [first]
            while len(batch) < self.batch_size and not self._tqueue.empty():
                try:
                    batch.append(self._tqueue.get_nowait())
                except thread_queue.Empty:
                    break
            try:
                self._persist_batch(batch)
            except Exception as exc:
                # The ledger may already have committed before a later
                # checkpoint/fsync failed. Retain the failure, never replay
                # the batch automatically or claim a successful drain.
                self._worker_failure = exc
                self._worker_stop.set()
                return

    def _check_worker_failure(self) -> None:
        if self._worker_failure is not None:
            raise RuntimeError(
                "evidence worker failed; commit outcome is unknown; inspect the ledger before recovery"
            ) from self._worker_failure

    def _record_drop_streak(self) -> None:
        """Append one loud line for the start of a drop-streak. Best-effort IO."""
        line = {
            "at": _utc_now_iso(),
            "event": "RECEIPT_DROPPED_FAIL_OPEN",
            "message": (
                "evidence queue full; receipts are being dropped and counted. "
                "This IS data loss in the audit trail — investigate the sink."
            ),
            "queue_maxsize": self.maxsize,
        }
        try:
            with open(self.drops_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, sort_keys=True) + "\n")
        except OSError:
            pass  # the counter in stats() is the durable signal either way

    def _require_queue(self) -> asyncio.Queue[PendingReceipt]:
        """The queue lives on the running loop; create it lazily per loop.

        asyncio.Queues became loop-unbound in modern Python, so we track the
        owning loop ourselves: a sink reused across *different* loops (test
        harnesses do this) gets a fresh queue rather than silently mixing
        loops — but within one loop the queue is created exactly once.
        """
        loop = asyncio.get_running_loop()
        if self._queue is None or self._queue_loop is not loop:
            self._queue = asyncio.Queue(maxsize=self.maxsize)
            self._queue_loop = loop
        return self._queue

    # ---------------------------------------------------------------- flusher

    async def start(self) -> None:
        """Boot the background flusher task (idempotent)."""
        if self.read_only:
            raise RuntimeError("read-only sinks inspect; they do not flush")
        self._check_worker_failure()
        flusher = self._flusher
        if flusher is not None and not flusher.done():
            if flusher.get_loop() is not asyncio.get_running_loop():
                raise RuntimeError("sink flusher is active on another event loop")
            return
        if flusher is not None and not flusher.cancelled():
            flusher.result()  # A failed flusher cannot silently restart.
        await self._finish_inflight()
        self._require_queue()
        if self._flusher is None or self._flusher.done():
            self._flusher = asyncio.create_task(
                self._flush_loop(), name=f"szl-evidence-flusher:{self.directory}"
            )

    async def aclose(self, timeout_s: float = 10.0) -> None:
        """Drain both lanes, or report incomplete shutdown without losing the writer."""
        if timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        cancelling_at_entry = asyncio.current_task().cancelling()
        self._worker_stop.set()
        try:
            async with asyncio.timeout(timeout_s):
                flusher = self._flusher
                if flusher is not None:
                    if not flusher.done():
                        flusher.cancel()
                    try:
                        await flusher
                    except asyncio.CancelledError:
                        # Suppress our flusher's cancellation, not cancellation
                        # of the close caller (including its timeout).
                        if asyncio.current_task().cancelling() > cancelling_at_entry:
                            raise
                await self._finish_inflight()
                worker = self._worker
                if worker is not None and worker.is_alive():
                    await asyncio.to_thread(worker.join, timeout_s)
                    if worker.is_alive():
                        raise TimeoutError("evidence worker is still running")
                self._check_worker_failure()
                for queue in (self._queue, self._tqueue):
                    while queue is not None:
                        batch = []
                        while len(batch) < self.batch_size:
                            try:
                                batch.append(queue.get_nowait())
                            except (asyncio.QueueEmpty, thread_queue.Empty):
                                break
                        if not batch:
                            break
                        await self._persist_async_batch(batch)
        except TimeoutError as exc:
            detail = (
                "worker is still running"
                if self._worker and self._worker.is_alive()
                else "write or drain is incomplete"
            )
            raise TimeoutError(f"sink shutdown exceeded {timeout_s}s; {detail}") from exc
        finally:
            # shutdown(wait=False) never cancels submitted writes. Their Future
            # remains usable from the next event loop after timeout/cancellation.
            executor = self._writer_executor
            if executor is not None:
                executor.shutdown(wait=False)
                self._writer_executor = None

    async def _finish_inflight(self) -> None:
        future = self._inflight
        if future is not None:
            await asyncio.shield(asyncio.wrap_future(future))
            if self._inflight is future:
                self._inflight = None

    async def _persist_async_batch(self, batch: list[PendingReceipt]) -> None:
        self._check_worker_failure()
        if self._writer_executor is None:
            self._writer_executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="szl-evidence-writer"
            )
        self._inflight = self._writer_executor.submit(self._persist_batch, batch)
        await self._finish_inflight()

    def drain_thread_lane(self, timeout_s: float | None = None) -> int:
        """Stop the thread-lane worker and synchronously persist its backlog.

        For shutdown paths without a running event loop. The worker exits on
        its stop flag without draining the thread-lane queue, so this persists
        whatever is still queued through :meth:`_persist_batch` in
        ``batch_size`` batches. It keeps draining while a racing producer adds
        receipts, and re-stops a worker that such a producer restarted
        (``_enqueue_thread`` restarts a dead worker and clears the flag).

        Returns how many receipts this call persisted; the worker's own final
        batch is not counted. Raises :class:`TimeoutError` if receipts are
        still queued, or a worker is still running, at the deadline: queued
        receipts are never abandoned silently. ``timeout_s`` defaults to
        ``max(5.0, 2 * flush_interval_s)`` so an idle worker always has time to
        notice the flag. Receipts enqueued after this returns are outside its
        guarantee; such an enqueue restarts the worker as usual.
        """
        if timeout_s is None:
            timeout_s = max(5.0, 2 * self.flush_interval_s)
        if timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        self._check_worker_failure()
        deadline = time.monotonic() + timeout_s
        persisted = 0
        while True:
            self._worker_stop.set()
            worker = self._worker
            if worker is not None and worker.is_alive():
                worker.join(timeout=max(0.0, deadline - time.monotonic()))
            self._check_worker_failure()
            persisted += self._drain_thread_queue(deadline)
            worker = self._worker
            running = worker is not None and worker.is_alive()
            queued = self._tqueue.qsize() if self._tqueue is not None else 0
            if not running and not queued:
                return persisted
            if time.monotonic() >= deadline:
                still = " and the worker is still running" if running else ""
                raise TimeoutError(
                    f"thread-lane drain exceeded {timeout_s}s: {queued} receipt(s) still "
                    f"queued{still}; this call persisted {persisted}"
                )

    # -------------------------------------------------------------- internals

    def _drain_thread_queue(self, deadline: float | None = None) -> int:
        """Persist what is on the thread-lane queue, in ``batch_size`` batches.

        Used by :meth:`drain_thread_lane`. Stops taking
        new batches once *deadline* (a ``time.monotonic()`` value) passes and
        leaves the rest queued for the caller to report. A batch taken off the
        queue is always handed to :meth:`_persist_batch`. Returns the count.
        """
        tqueue = self._tqueue
        self._check_worker_failure()
        persisted = 0
        while tqueue is not None and (deadline is None or time.monotonic() < deadline):
            batch: list[PendingReceipt] = []
            while len(batch) < self.batch_size:
                try:
                    batch.append(tqueue.get_nowait())
                except thread_queue.Empty:
                    break
            if not batch:
                break
            persisted += self._persist_batch(batch)
        return persisted

    async def _flush_loop(self) -> None:
        """Batch receipts (size `batch_size` or age `flush_interval_s`) and persist.

        The blocking file IO runs on a dedicated executor so the event loop
        — usually the *user's LLM request loop* — never stalls on an fsync.
        The completion future also survives a change of event loop.
        """
        while True:
            queue = self._require_queue()
            try:
                # ``asyncio.wait_for`` can swallow an external cancellation on
                # Python 3.11 when queue delivery races shutdown. The timeout
                # context distinguishes its own deadline from aclose()'s cancel.
                async with asyncio.timeout(self.flush_interval_s):
                    first = await queue.get()
            except TimeoutError:
                continue  # idle period: nothing signed, nothing to persist
            batch = [first]
            while len(batch) < self.batch_size and not queue.empty():
                batch.append(queue.get_nowait())
            await self._persist_async_batch(batch)

    def _persist_batch(self, batch: list[PendingReceipt]) -> int:
        """Chain *batch* onto the tail in memory, then replace the ledger atomically.

        Returns the persisted count. The in-memory chain is read back fresh
        from disk each batch — the ledger file is the single source of truth.
        The full new ledger is written and fsynced to a temp file, then
        renamed over ``receipts.jsonl`` (:meth:`_replace_ledger`), so a crash
        at any point, including in the middle of this batch, leaves either
        the previous ledger or the new one: receipts already fsynced are never
        lost. If writing fails, the ledger is untouched, the temp file is
        removed and the error propagates; the batch did not commit. Serialized
        across the asyncio and thread lanes by ``_persist_lock``.
        """
        with self._persist_lock:
            entries = self._read_jsonl(self.log_path)
            for pending in batch:
                chain_append(entries, pending.receipt)
                self._write_sidecar(pending)
            lines = "".join(
                json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n" for entry in entries
            )
            self._replace_ledger(lines)
            self._write_checkpoint(entries)
        return len(batch)

    def _replace_ledger(self, lines: str) -> None:
        """Crash-atomically make *lines* the whole content of ``receipts.jsonl``.

        1. Write to a new, uniquely named temp file in the sink directory (same
           filesystem, so the rename is atomic), in the same text mode the
           ledger has always been written with, so the bytes are unchanged.
        2. Flush and fsync it, so its bytes are durable before the ledger
           name points at them. On POSIX it takes the old ledger's mode bits.
        3. ``os.replace`` it over the ledger: readers see the old file or the
           new one, never a mix.
        4. On POSIX, fsync the directory so the rename itself is durable.
           Windows cannot fsync a directory; that step is skipped there.

        On an exception the temp file is removed and the ledger is never
        opened, truncated or unlinked. A hard kill can leave a stale
        ``.receipts.jsonl.*.tmp``; nothing reads it and the ledger is intact.
        """
        tmp = self.directory / f".{CHAIN_LOG_FILE}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        fh = open(tmp, "x", encoding="utf-8")  # O_EXCL: never adopts an existing file
        try:
            with fh:
                fh.write(lines)
                fh.flush()
                os.fsync(fh.fileno())
            if _POSIX and self.log_path.exists():
                os.chmod(tmp, stat.S_IMODE(self.log_path.stat().st_mode))
            self._rename_over_ledger(tmp)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise
        if _POSIX:
            self._fsync_directory()

    def _rename_over_ledger(self, tmp: Path) -> None:
        for attempt in range(_REPLACE_RETRIES + 1):
            try:
                os.replace(tmp, self.log_path)
                return
            except PermissionError:
                if attempt >= _REPLACE_RETRIES:
                    raise
                time.sleep(_REPLACE_RETRY_DELAY_S)

    def _fsync_directory(self) -> None:
        """Make the rename durable. Tolerates only "unsupported" errors."""
        try:
            fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            if exc.errno not in _DIR_FSYNC_UNSUPPORTED:
                raise

    def _write_sidecar(self, pending: PendingReceipt) -> None:
        """Materialize the evidence document at its content-addressed path."""
        blob = jcs_canon_bytes(pending.evidence_doc)
        target = _evidence_path(self.directory, pending.evidence_uri, sha256_hex(blob))
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(blob)

    def _write_checkpoint(self, entries: list[dict[str, Any]]) -> None:
        if not entries:
            return
        head = entries[-1]
        checkpoint = {
            "at": _utc_now_iso(),
            "entries": len(entries),
            "entry_digest": head["entry_digest"],
            "seq": head["seq"],
        }
        tmp = self.checkpoint_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(checkpoint, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.checkpoint_path)  # atomic rename: readers never see a half file

    # ------------------------------------------------------------------ reads

    @staticmethod
    def _read_jsonl(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        size = path.stat().st_size
        if size == 0:
            return []
        out: list[dict[str, Any]] = []
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise SinkBootError(
                        f"{path}:{lineno}: unreadable chain line ({exc}) — "
                        "the ledger may be torn; refusing to continue"
                    ) from exc
        return out

    def iterate(self) -> Iterator[dict[str, Any]]:
        """Yield chain entries in order (read-only; safe without a running loop)."""
        yield from self._read_jsonl(self.log_path)

    def receipt_by_id(
        self, receipt_id: str
    ) -> tuple[dict[str, Any], dict[str, Any] | None] | None:
        """Look up ``(receipt, evidence_doc)`` by receipt id, or None."""
        for entry in self._read_jsonl(self.log_path):
            receipt = entry.get("receipt", {})
            if receipt.get("receipt_id") == receipt_id:
                evidence_doc = None
                for ev in receipt.get("evidence", []):
                    if not isinstance(ev, dict):
                        continue
                    try:
                        sidecar = _evidence_path(self.directory, ev.get("uri"), ev.get("sha256"))
                        evidence_doc = json.loads(sidecar.read_text(encoding="utf-8"),
                                                 object_pairs_hook=_unique_json_object)
                    except (OSError, ValueError, RecursionError):
                        evidence_doc = None
                return receipt, evidence_doc
        return None

    def stats(self) -> dict[str, Any]:
        """Operational truth about the sink, including the loud drop counter."""
        entries = self._read_jsonl(self.log_path)
        checkpoint = None
        if self.checkpoint_path.exists():
            try:
                checkpoint = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                checkpoint = None
        queued = self._queue.qsize() if self._queue is not None else 0
        if self._tqueue is not None:
            queued += self._tqueue.qsize()
        return {
            "sink_dir": str(self.directory),
            "read_only": self.read_only,
            "fail_mode": self.policy.fail_mode.value,
            "required_before_response": self.policy.require_receipt_before_response,
            "entries": len(entries),
            "queued": queued,
            "dropped_counter": self._dropped,
            "worker_failed": self._worker_failure is not None,
            "worker_failure_type": (
                type(self._worker_failure).__name__ if self._worker_failure else None
            ),
            "head": entries[-1]["entry_digest"] if entries else None,
            "checkpoint": checkpoint,
        }


def verify_sink(path: str | Path) -> dict[str, Any]:
    """Verify the on-disk chain at *path* and return a report dict.

    Synchronous, loop-free, read-only — safe to call from a CLI or a health
    endpoint. ``ok`` mirrors :func:`szl_receipts.verify_chain`; the report is
    findings-rich so an auditor reads *which* attack pattern fired.

    Beyond the chain itself, every receipt's evidence sidecar is re-hashed
    and compared with the digest the receipt committed to, and the file is
    checked at its content-addressed path (``evidence/<digest>.json``). A
    missing, substituted, malformed, or mislocated sidecar flips ``ok`` to
    False. Existing symlinks and special files are rejected before opening.
    """
    base = Path(path)
    log_path = base / CHAIN_LOG_FILE
    entries = EvidenceSink._read_jsonl(log_path)
    report = verify_chain(entries)
    out = report.to_dict()
    sidecars = {"checked": 0, "missing": 0, "mismatched": 0, "invalid": 0}
    findings: list[dict[str, Any]] = out["findings"]
    for entry in entries:
        receipt = entry.get("receipt", {}) if isinstance(entry, dict) else {}
        if not isinstance(receipt, dict) or not isinstance(receipt.get("evidence", []), list):
            continue  # The chain verifier already reports the invalid receipt shape.
        for ev in receipt.get("evidence", []):
            if not isinstance(ev, dict):
                continue
            uri = ev.get("uri")
            want = ev.get("sha256")
            sidecars["checked"] += 1
            try:
                target = _evidence_path(base, uri, want)
                doc = json.loads(target.read_text(encoding="utf-8"),
                                 object_pairs_hook=_unique_json_object)
                got = sha256_hex(jcs_canon_bytes(doc))
            except FileNotFoundError:
                sidecars["missing"] += 1
                findings.append(
                    {"code": "evidence-missing", "message": f"sidecar not found: {uri}"}
                )
                continue
            except (OSError, ValueError, TypeError, RecursionError, JcsError) as exc:
                sidecars["invalid"] += 1
                findings.append({"code": "evidence-invalid",
                                 "message": f"sidecar rejected: {type(exc).__name__}"})
                continue
            if got != want:
                sidecars["mismatched"] += 1
                findings.append(
                    {
                        "code": "evidence-mismatch",
                        "message": f"sidecar {uri} rehashes to {got}, receipt commits to {want}",
                    }
                )
    out["sidecars"] = sidecars
    out["ok"] = report.ok and not any(sidecars[key] for key in ("missing", "mismatched", "invalid"))
    out["sink"] = str(base)
    out["chain_log"] = str(log_path)
    return out
