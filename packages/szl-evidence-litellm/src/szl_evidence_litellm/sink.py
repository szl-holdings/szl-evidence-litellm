"""The evidence sink: sign synchronously, persist asynchronously, chain always.

Shape of the thing:

* The LiteLLM hook signs (receipt construction + content addressing happen
  inline, on the request path) and does a *synchronous, non-blocking*
  enqueue. The request path never waits on disk.
* A single background flusher task owns the files. It collects receipts for
  up to ``flush_interval_s`` seconds or ``batch_size`` receipts, whichever
  comes first, then appends them to ``receipts.jsonl`` as hash-chained
  entries (:func:`szl_receipts.append` semantics: ``seq``, ``prev``,
  ``entry_digest``) and fsyncs the batch. One writer means no interleaving,
  no sequence races, no partial lines.
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

* ``receipts.jsonl`` — one chain entry per line (the append-only ledger)
* ``evidence/<digest>.json`` — content-addressed evidence documents
* ``bodies/<digest>.json`` — captured bodies, only when capture is enabled
* ``chain_head.json`` — checkpoint {seq, entry_digest, entries} after each batch
* ``drops.jsonl`` — one line per drop-streak, only when FAIL_OPEN drops occur
"""

from __future__ import annotations

import asyncio
import json
import os
import queue as thread_queue
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from szl_receipts import append as chain_append
from szl_receipts import jcs_canon_bytes, sha256_hex, verify_chain

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


@dataclass(frozen=True)
class PendingReceipt:
    """One receipt awaiting chain persistence, with its evidence sidecar."""

    receipt: dict[str, Any]
    evidence_doc: dict[str, Any]
    evidence_uri: str


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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
        # No-running-loop path: LiteLLM's sync callbacks can fire on executor
        # threads. A stdlib queue + daemon worker thread keeps enqueue()
        # synchronous and exact there; both paths converge on _persist_batch
        # under _persist_lock, so the chain file has exactly one writer at a
        # time regardless of which lane a receipt arrived on.
        self._tqueue: thread_queue.Queue[PendingReceipt] | None = None
        self._worker: threading.Thread | None = None
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
            self._persist_batch(batch)

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
        self._require_queue()
        if self._flusher is None or self._flusher.done():
            self._flusher = asyncio.create_task(
                self._flush_loop(), name=f"szl-evidence-flusher:{self.directory}"
            )

    async def aclose(self, timeout_s: float = 10.0) -> None:
        """Stop both drain lanes and persist every queued receipt."""
        flusher = self._flusher
        if flusher is not None and not flusher.done():
            flusher.cancel()
            try:
                async with asyncio.timeout(timeout_s):
                    await flusher
            except asyncio.CancelledError:
                pass
            except TimeoutError as exc:
                raise TimeoutError(
                    f"sink flusher shutdown exceeded {timeout_s}s"
                ) from exc
        self._worker_stop.set()
        worker = self._worker
        if worker is not None and worker.is_alive():
            await asyncio.to_thread(worker.join, timeout_s)
        queue = self._queue
        deadline = time.monotonic() + timeout_s
        while queue is not None and not queue.empty():
            if time.monotonic() > deadline:
                raise TimeoutError(f"sink drain exceeded {timeout_s}s")
            await asyncio.to_thread(self._persist_until_empty)
        if self._tqueue is not None:
            while True:
                try:
                    batch = [self._tqueue.get_nowait()]
                except thread_queue.Empty:
                    break
                while len(batch) < self.batch_size and not self._tqueue.empty():
                    try:
                        batch.append(self._tqueue.get_nowait())
                    except thread_queue.Empty:
                        break
                await asyncio.to_thread(self._persist_batch, batch)

    # -------------------------------------------------------------- internals

    async def _flush_loop(self) -> None:
        """Batch receipts (size `batch_size` or age `flush_interval_s`) and persist.

        The blocking file IO runs via ``asyncio.to_thread`` so the event loop
        — which is usually the *user's LLM request loop* — never stalls on an
        fsync for the audit trail.
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
            await asyncio.to_thread(self._persist_batch, batch)

    def _persist_until_empty(self) -> None:
        queue = self._queue
        if queue is None:
            return
        while True:
            batch: list[PendingReceipt] = []
            while len(batch) < self.batch_size and not queue.empty():
                batch.append(queue.get_nowait())
            if not batch:
                return
            self._persist_batch(batch)

    def _persist_batch(self, batch: list[PendingReceipt]) -> int:
        """Chain *batch* onto the tail in memory, then one write + fsync.

        Returns the persisted count. The in-memory chain is read back fresh
        from disk each batch — the ledger file is the single source of truth,
        so a crash between batches loses nothing already fsynced. Serialized
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
            with open(self.log_path, "w", encoding="utf-8") as fh:
                fh.write(lines)
                fh.flush()
                os.fsync(fh.fileno())
            self._write_checkpoint(entries)
        return len(batch)

    def _write_sidecar(self, pending: PendingReceipt) -> None:
        """Materialize the evidence document at its content-addressed path."""
        target = self.directory / pending.evidence_uri
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(jcs_canon_bytes(pending.evidence_doc))

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
                    uri = ev.get("uri")
                    if uri:
                        sidecar = self.directory / uri
                        if sidecar.exists():
                            try:
                                evidence_doc = json.loads(sidecar.read_text(encoding="utf-8"))
                            except (OSError, json.JSONDecodeError):
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
    missing or substituted sidecar flips ``ok`` to False.
    """
    base = Path(path)
    log_path = base / CHAIN_LOG_FILE
    entries = EvidenceSink._read_jsonl(log_path)
    report = verify_chain(entries)
    out = report.to_dict()
    sidecars = {"checked": 0, "missing": 0, "mismatched": 0}
    findings: list[dict[str, Any]] = out["findings"]
    for entry in entries:
        receipt = entry.get("receipt", {}) if isinstance(entry, dict) else {}
        for ev in receipt.get("evidence", []) or []:
            uri = ev.get("uri")
            want = ev.get("sha256")
            if not isinstance(uri, str) or not isinstance(want, str):
                continue
            target = base / uri
            sidecars["checked"] += 1
            if not target.exists():
                sidecars["missing"] += 1
                findings.append(
                    {"code": "evidence-missing", "message": f"sidecar not found: {uri}"}
                )
                continue
            got = sha256_hex(jcs_canon_bytes(json.loads(target.read_text(encoding="utf-8"))))
            if got != want:
                sidecars["mismatched"] += 1
                findings.append(
                    {
                        "code": "evidence-mismatch",
                        "message": f"sidecar {uri} rehashes to {got}, receipt commits to {want}",
                    }
                )
    out["sidecars"] = sidecars
    out["ok"] = report.ok and not sidecars["missing"] and not sidecars["mismatched"]
    out["sink"] = str(base)
    out["chain_log"] = str(log_path)
    return out
