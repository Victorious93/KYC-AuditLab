"""Minimal CLI over IdentityShieldClient, for controllers/host tools that
shell out (e.g. Droidcommand-AI) and for manual use.

    export IDENTITYSHIELD_API_KEY=...        # runtime only; never on the command line
    python -m app.client whoami
    python -m app.client modules
    python -m app.client run --module api.auth.missing_token_rejected --target 127.0.0.1:8000 [--params '{"k":"v"}']
    python -m app.client run-layer --layer layer5_api --target 127.0.0.1:8000
    python -m app.client runs
    python -m app.client run-get <run_id>
    python -m app.client scope

Output is JSON on stdout. The key is read from the environment only (a
``--api-key`` flag would leak into shell history / process lists); the token
is never printed. Exit codes: 0 ok, 2 config error, 3 auth error,
4 rate limited, 1 other API error. The token is revoked on exit.
"""
from __future__ import annotations

import argparse
import json
import sys

from .session import AuthError, ClientError, ConfigError, IdentityShieldClient, RateLimited


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m app.client", description=__doc__.split("\n\n")[0])
    p.add_argument("--base-url", help="API base URL (default: $IDENTITYSHIELD_API_URL or http://127.0.0.1:8000)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("whoami", help="sign in and print identity, roles, expires_at")
    sub.add_parser("modules", help="GET /tests/modules (operator)")
    r = sub.add_parser("run", help="POST /tests/run (operator)")
    r.add_argument("--module", required=True)
    r.add_argument("--target", required=True)
    r.add_argument("--params", help="JSON object of module params")
    rl = sub.add_parser("run-layer", help="POST /tests/run-layer (operator)")
    rl.add_argument("--layer", required=True)
    rl.add_argument("--target", required=True)
    sub.add_parser("runs", help="GET /results/runs (operator)")
    g = sub.add_parser("run-get", help="GET /results/runs/{id} (operator)")
    g.add_argument("run_id")
    sub.add_parser("scope", help="GET /scope (admin)")
    return p


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        params = json.loads(args.params) if getattr(args, "params", None) else None
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"--params is not valid JSON: {exc}"}), file=sys.stderr)
        return 2
    try:
        with IdentityShieldClient(base_url=args.base_url) as c:
            if args.cmd == "whoami":
                out = c.sign_in()
            elif args.cmd == "modules":
                out = c.list_modules()
            elif args.cmd == "run":
                out = c.run_module(args.module, args.target, params)
            elif args.cmd == "run-layer":
                out = c.run_layer(args.layer, args.target)
            elif args.cmd == "runs":
                out = c.list_runs()
            elif args.cmd == "run-get":
                out = c.get_run(args.run_id)
            else:
                out = c.list_scope()
    except ConfigError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    except AuthError as exc:
        print(json.dumps({"error": str(exc), "status": exc.status, "detail": exc.detail}), file=sys.stderr)
        return 3
    except RateLimited as exc:
        print(json.dumps({"error": str(exc), "retry_after": exc.retry_after}), file=sys.stderr)
        return 4
    except ClientError as exc:
        print(json.dumps({"error": str(exc), "status": exc.status, "detail": exc.detail}), file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
