"""python -m szl_evidence_litellm — the operator surface.

Commands:

* ``demo-proxy --port 8420`` — boot the offline demo proxy (local
  deterministic demo backend — not an LLM), receipt every request, echo the
  correlation id in ``x-szl-receipt-id``.
* ``verify --sink PATH`` — verify the sink's hash chain from genesis and
  print a findings-rich report. Exit 0 iff the chain is intact.
* ``stats --sink PATH`` — read-only operational truth: entry count, head
  digest, drop counter, checkpoint.

``--json`` prints the machine form everywhere; ``--help`` is always free.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .sink import EvidenceSink, verify_sink

__all__ = ["main"]


def _print(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    for key, value in payload.items():
        if isinstance(value, dict | list):
            print(f"{key}:")
            print(json.dumps(value, indent=2, sort_keys=True))
        else:
            print(f"{key}: {value}")


def _cmd_verify(args: argparse.Namespace) -> int:
    report = verify_sink(args.sink)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        verdict = "OK — chain intact" if report["ok"] else "FAILED — chain tampered or broken"
        print(f"sink:     {report['sink']}")
        print(f"entries:  {report['length']}")
        print(f"head:     {report['head']}")
        print(f"verdict:  {verdict}")
        for finding in report["findings"]:
            print(f"  [{finding['code']}] {finding['message']}")
    return 0 if report["ok"] else 1


def _cmd_stats(args: argparse.Namespace) -> int:
    sink = EvidenceSink(args.sink, read_only=True)
    payload = sink.stats()
    _print(payload, args.json)
    return 0


def _cmd_demo_proxy(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from .proxy import create_app
    except ImportError as exc:
        print(
            f"demo-proxy unavailable: {exc}",
            file=sys.stderr,
        )
        return 2
    app = create_app(sink_dir=args.sink)
    print(f"szl-evidence demo proxy on http://{args.host}:{args.port}", file=sys.stderr)
    print(f"sink: {args.sink} (verify with: python -m szl_evidence_litellm verify "
          f"--sink {args.sink})", file=sys.stderr)
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="szl_evidence_litellm",
        description=(
            "SZL Evidence Plane plugin for LiteLLM — tamper-evident, hash-chained "
            "receipts for every LLM request."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo-proxy", help="run the offline demo proxy")
    demo.add_argument("--host", default="127.0.0.1")
    demo.add_argument("--port", type=int, default=8420)
    demo.add_argument("--sink", default="./szl-evidence", help="sink directory")
    demo.add_argument("--log-level", default="warning")
    demo.set_defaults(func=_cmd_demo_proxy)

    verify = sub.add_parser("verify", help="verify a sink's hash chain from genesis")
    verify.add_argument("--sink", required=True, help="sink directory")
    verify.add_argument("--json", action="store_true", help="machine-readable output")
    verify.set_defaults(func=_cmd_verify)

    stats = sub.add_parser("stats", help="read-only sink counters and head")
    stats.add_argument("--sink", required=True, help="sink directory")
    stats.add_argument("--json", action="store_true", help="machine-readable output")
    stats.set_defaults(func=_cmd_stats)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
