"""Doc test: the README examples must run against the real package API.

The repository README's ``## Quick start`` and the plugin README's
``## Use it from the SDK`` python blocks are extracted verbatim and executed
against the installed ``szl_evidence_litellm`` package, in a temporary
working directory, with a stub ``litellm`` module standing in for the real
one. The tests then assert that the documented constructor and callback
registration produce a real ``SZLEvidenceLogger`` wired to a real
``EvidenceSink``, and that the documented verify command passes on the
resulting sink.

Nothing here contacts a model provider: ``litellm`` is a stub whose
``completion`` only records its arguments, and outbound connections to any
non-loopback address raise for the duration of each test. (Loopback stays
open because asyncio's self-pipe on Windows is a localhost socket pair.)
"""

from __future__ import annotations

import asyncio
import re
import shlex
import socket
import sys
import time
import types
from pathlib import Path

import pytest
from szl_evidence_litellm import EvidenceSink, SZLEvidenceLogger, verify_sink
from szl_evidence_litellm.cli import main as cli_main

REPO = Path(__file__).resolve().parents[1]
ROOT_README = REPO / "README.md"
PLUGIN_README = REPO / "packages" / "szl-evidence-litellm" / "README.md"

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def fenced_block(readme: Path, heading: str, lang: str) -> str:
    """Return the first ```lang fenced block under the ``## heading`` section."""
    text = readme.read_text(encoding="utf-8")
    section = re.search(
        rf"^## {re.escape(heading)}[ \t]*\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL
    )
    assert section, f"{readme.name}: no '## {heading}' section"
    block = re.search(rf"^```{lang}[ \t]*\n(.*?)^```", section.group(1), re.MULTILINE | re.DOTALL)
    assert block, f"{readme.name}: no ```{lang} block under '## {heading}'"
    return block.group(1)


def run_block(code: str, label: str) -> dict:
    namespace: dict = {"__name__": "__readme__"}
    exec(compile(code, label, "exec"), namespace)  # noqa: S102 - our own README, not model output
    return namespace


@pytest.fixture()
def offline(monkeypatch):
    """Refuse any outbound connection or lookup that is not loopback."""
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _host(address):
        return address[0] if isinstance(address, tuple) else address

    def _guard(address):
        if _host(address) not in _LOOPBACK:
            raise AssertionError(f"README example attempted a network connection to {address!r}")

    def connect(self, address):
        _guard(address)
        return real_connect(self, address)

    def connect_ex(self, address):
        _guard(address)
        return real_connect_ex(self, address)

    def getaddrinfo(host, *args, **kwargs):
        _guard((host,))
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


@pytest.fixture()
def stub_litellm(monkeypatch):
    """A stand-in ``litellm`` module: a callbacks list and a recording completion."""
    stub = types.ModuleType("litellm")
    stub.callbacks = []
    stub.completion_calls = []

    def completion(**kwargs):
        stub.completion_calls.append(kwargs)
        return {"id": "stub-completion", "object": "chat.completion", "choices": []}

    stub.completion = completion
    monkeypatch.setitem(sys.modules, "litellm", stub)
    return stub


def test_root_quickstart_runs_against_the_real_api(tmp_path, monkeypatch, stub_litellm, offline):
    if not ROOT_README.is_file():
        pytest.skip("repository README not present (not a repository checkout)")
    code = fenced_block(ROOT_README, "Quick start", "python")
    monkeypatch.chdir(tmp_path)

    namespace = run_block(code, f"{ROOT_README.name}: ## Quick start")

    # The documented registration installs exactly one real SZLEvidenceLogger.
    assert len(stub_litellm.callbacks) == 1, stub_litellm.callbacks
    (logger,) = stub_litellm.callbacks
    assert isinstance(logger, SZLEvidenceLogger)
    sink = logger.sink
    assert isinstance(sink, EvidenceSink)
    assert logger.policy is sink.policy
    assert namespace.get("sink") is sink
    # The sink argument is a directory, created inside the working directory.
    assert sink.directory.is_dir()
    assert sink.directory.resolve().parent == tmp_path.resolve()
    assert stub_litellm.completion_calls == []

    # One synthetic success event through the registered logger, using the
    # asyncio lifecycle the README documents (start, then aclose to drain).
    async def one_call() -> None:
        await sink.start()
        await logger.async_log_success_event(
            {
                "litellm_call_id": "readme-quickstart-1",
                "model": "demo",
                "messages": [{"role": "user", "content": "hello"}],
            },
            {
                "id": "demo-1",
                "object": "chat.completion",
                "model": "demo",
                "choices": [{"index": 0, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
            time.time(),
            time.time(),
        )
        await logger.aclose()

    asyncio.run(one_call())

    # The documented verify command, run in-process, passes on that sink.
    bash = fenced_block(ROOT_README, "Quick start", "bash")
    commands = [line.strip() for line in bash.splitlines() if line.strip().startswith("python ")]
    assert len(commands) == 1, commands
    argv = shlex.split(commands[0])
    assert argv[:3] == ["python", "-m", "szl_evidence_litellm"], commands[0]
    assert cli_main(argv[3:]) == 0

    report = verify_sink(sink.directory)
    assert report["ok"], report["findings"]
    assert report["length"] == 1


def test_plugin_readme_sdk_example_registers_the_logger(
    tmp_path, monkeypatch, stub_litellm, offline
):
    code = fenced_block(PLUGIN_README, "Use it from the SDK", "python")
    monkeypatch.chdir(tmp_path)

    run_block(code, f"{PLUGIN_README.name}: ## Use it from the SDK")

    assert len(stub_litellm.callbacks) == 1, stub_litellm.callbacks
    (logger,) = stub_litellm.callbacks
    assert isinstance(logger, SZLEvidenceLogger)
    assert isinstance(logger.sink, EvidenceSink)
    assert logger.policy is logger.sink.policy
    assert logger.sink.directory.is_dir()
    assert logger.sink.directory.resolve().parent == tmp_path.resolve()
    # The example's completion call reached the stub and nothing else.
    assert len(stub_litellm.completion_calls) == 1
