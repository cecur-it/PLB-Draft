"""Caido client bootstrap.

The Caido CLI runs as an in-container sidecar listening on
``127.0.0.1:48080`` *inside* the sandbox. We grab a guest token by
``session.exec()``-ing curl from inside the container, then construct
a host-side :class:`caido_sdk_client.Client` against the runtime's
exposed-port URL for all subsequent SDK calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


# Readiness is time-bounded rather than attempt-bounded: a fresh sandbox
# container is still running its entrypoint while the first probe fires, and the
# probe can also be *slow* (the sandbox exec is queued behind workspace
# materialisation), in which case an attempt-counted loop burns all its
# iterations on timeouts and gives up while Caido is about to come up.
_READY_DEADLINE_S = 180.0
_PROBE_TIMEOUT_S = 20.0


async def _login_as_guest(
    session: BaseSandboxSession,
    *,
    container_url: str,
    attempts: int | None = None,
    deadline_s: float = _READY_DEADLINE_S,
) -> str:
    """``session.exec`` curl to fetch a guest token; retry until ready.

    Caido's GraphQL listener may not be up the instant the container
    starts. The retry loop also doubles as the Caido readiness probe —
    no separate TCP healthcheck needed.

    ``attempts`` is kept for callers that want a hard iteration cap; the
    default is a wall-clock deadline so a slow-but-healthy sandbox is not
    mistaken for a dead one.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + deadline_s
    last_err: str | None = None
    i = 0
    while True:
        i += 1
        try:
            result = await session.exec(
                "curl",
                "-fsS",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                _LOGIN_AS_GUEST_BODY,
                f"{container_url}/graphql",
                timeout=_PROBE_TIMEOUT_S,
            )
        except Exception as exc:  # noqa: BLE001 - transport/timeout, retried below
            # The sandbox exec can time out or drop its transport while the
            # container finishes booting; that is a retryable condition, not a
            # reason to fail the whole bootstrap.
            last_err = f"exec failed: {type(exc).__name__}: {exc}"
        else:
            if result.ok():
                try:
                    payload = json.loads(result.stdout)
                    token = (
                        payload.get("data", {})
                        .get("loginAsGuest", {})
                        .get("token", {})
                        .get("accessToken")
                    )
                    if token:
                        return str(token)
                    last_err = f"loginAsGuest returned no token: {payload}"
                except json.JSONDecodeError as exc:
                    last_err = f"unparseable response: {exc}: {result.stdout!r}"
            else:
                stderr = result.stderr.decode("utf-8", errors="replace")[:200]
                last_err = f"curl exit {result.exit_code}: {stderr}"

        over_attempts = attempts is not None and i >= attempts
        if over_attempts or loop.time() >= deadline:
            raise RuntimeError(
                f"loginAsGuest failed after {i} attempt(s)/{deadline_s:.0f}s: {last_err}",
            )
        logger.debug("loginAsGuest attempt %d failed: %s", i, last_err)
        await asyncio.sleep(min(2.0 * i, 8.0))


async def bootstrap_caido(
    session: BaseSandboxSession,
    *,
    host_url: str,
    container_url: str,
) -> Client:
    """Connect to the in-container Caido sidecar and select a fresh project."""
    # The Caido SDK (and its generated GraphQL schema) is slow to import and is
    # only needed once a sandbox is actually being bootstrapped, so it is
    # imported here rather than at module scope.
    from caido_sdk_client import Client, TokenAuthOptions
    from caido_sdk_client.types import CreateProjectOptions

    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

    access_token = await _login_as_guest(session, container_url=container_url)

    client = Client(host_url, auth=TokenAuthOptions(token=access_token))
    try:
        # connect() is inside the guard as well: a cancellation there (scan
        # teardown while the bootstrap is still in flight) would otherwise
        # leave the half-connected transport behind.
        await client.connect()
        project = await client.project.create(
            CreateProjectOptions(name="sandbox", temporary=True),
        )
        await client.project.select(project.id)
    except BaseException:
        # The client never reaches the session bundle if connect or project
        # setup fails, so close it here to avoid leaking the transport.
        with contextlib.suppress(Exception):
            await client.aclose()
        raise
    logger.info("Caido project selected: %s", project.id)
    return client
