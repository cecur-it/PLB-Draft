#!/usr/bin/env python3
"""dind-ready.py - Docker-in-Docker readiness helper for the errow orchestrator image.

Traces: CONTRACT §2 (errow-dind sidecar, DOCKER_HOST), §11 (healthchecks), §12 (idempotent bring-up).
Runs with the errow venv interpreter, so it reuses the Docker SDK that Errow itself depends on and
honours DOCKER_HOST / DOCKER_TLS_VERIFY / DOCKER_CERT_PATH exactly like Errow's runtime does.

  dind-ready.py ping [--timeout SECONDS]     wait until the Docker daemon answers (exit 0 ready, 1 timeout)
  dind-ready.py has-image IMAGE              exit 0 when IMAGE exists in the daemon, 1 otherwise
  dind-ready.py load TARBALL                 docker load a saved sandbox image (air-gap), exit 0 on success
Exit codes: 0 ok, 1 not ready / missing, 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
import time

try:
    import docker
    from docker.errors import DockerException, ImageNotFound
except ImportError as exc:  # pragma: no cover - only when run outside the errow venv
    sys.stderr.write(f"dind-ready: Docker SDK not importable ({exc}); run with the errow venv python\n")
    raise SystemExit(2) from exc


def client(timeout: int = 10) -> docker.DockerClient:
    return docker.from_env(timeout=timeout)


def cmd_ping(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout
    last = "no attempt made"
    while True:
        try:
            if client(5).ping():
                return 0
            last = "daemon did not answer ping"
        except DockerException as exc:
            last = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        except OSError as exc:
            last = str(exc)
        if time.monotonic() >= deadline:
            sys.stderr.write(f"dind-ready: Docker daemon not ready: {last}\n")
            return 1
        time.sleep(min(2.0, max(0.1, deadline - time.monotonic())))


def cmd_has_image(args: argparse.Namespace) -> int:
    try:
        client().images.get(args.image)
    except ImageNotFound:
        return 1
    except DockerException as exc:
        sys.stderr.write(f"dind-ready: {exc}\n")
        return 1
    return 0


def cmd_load(args: argparse.Namespace) -> int:
    try:
        with open(args.tarball, "rb") as handle:
            images = client(600).images.load(handle)
    except (OSError, DockerException) as exc:
        sys.stderr.write(f"dind-ready: cannot load {args.tarball}: {exc}\n")
        return 1
    for image in images:
        sys.stdout.write(f"loaded {', '.join(image.tags) or image.short_id}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dind-ready.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    ping = sub.add_parser("ping", help="wait for the Docker daemon")
    ping.add_argument("--timeout", type=int, default=120)
    ping.set_defaults(func=cmd_ping)
    has = sub.add_parser("has-image", help="check that an image exists")
    has.add_argument("image")
    has.set_defaults(func=cmd_has_image)
    load = sub.add_parser("load", help="docker load a tarball")
    load.add_argument("tarball")
    load.set_defaults(func=cmd_load)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
