"""Shared fixtures for the errow-mcp tests (policy fake resolver, fake Docker client, throwaway PKI)."""

from __future__ import annotations

import datetime
import ipaddress
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from policy import Policy  # noqa: E402

POLICY_FILE = HERE.parent / "policy.yaml"

DNS = {
    "scan-target.vendetta.lab": ["10.77.0.5"],
    "www.vendetta.lab": ["10.77.0.6"],
    "rebind.vendetta.lab": ["127.0.0.1"],
    "meta.vendetta.lab": ["169.254.169.254"],
    "mixed.vendetta.lab": ["10.77.0.7", "169.254.169.254"],
}


def fake_resolver(host: str) -> list[str]:
    try:
        return DNS[host]
    except KeyError:
        raise OSError(f"NXDOMAIN {host}") from None


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def policy(clock: Clock) -> Policy:
    return Policy.load(POLICY_FILE, resolver=fake_resolver, clock=clock)


class FakeContainer:
    def __init__(self, parent: FakeContainers, kwargs: dict[str, Any], *, output: list[Any] | None = None,
                 exit_code: int = 0, block_until_killed: bool = False) -> None:
        self.parent = parent
        self.kwargs = kwargs
        self.id = "c0ffee" + "0" * 58
        self.labels = kwargs.get("labels", {})
        self.attrs: dict[str, Any] = {"Created": "2026-01-01T00:00:00Z"}
        self._output = output if output is not None else [(b"ok\n", None)]
        self._exit = exit_code
        self._block = block_until_killed
        self._killed = threading.Event()
        self.exec_calls: list[dict[str, Any]] = []
        self.exec_results: list[Any] = []

    def attach(self, **kw: Any) -> Any:
        self.parent.calls.append("attach")
        assert kw.get("stream") and kw.get("demux")
        return iter(self._output)

    def start(self) -> None:
        self.parent.calls.append("start")

    def wait(self, timeout: float | None = None, condition: str | None = None) -> dict[str, int]:
        self.parent.calls.append(f"wait:{condition}")
        if self._block:
            self._killed.wait(timeout=10)
            return {"StatusCode": 137}
        return {"StatusCode": self._exit}

    def kill(self) -> None:
        self.parent.calls.append("kill")
        self._killed.set()

    def remove(self, force: bool = False) -> None:
        self.parent.calls.append(f"remove:{force}")
        self.parent.removed += 1

    def exec_run(self, cmd: list[str], **kw: Any) -> Any:
        self.exec_calls.append({"cmd": cmd, **kw})

        class R:
            pass

        res = R()
        res.exit_code, res.output = self.exec_results.pop(0) if self.exec_results else (0, (b"ok\n", None))
        return res


class FakeNetwork:
    def __init__(self, containers: dict[str, dict[str, str]] | None = None) -> None:
        self.attrs = {"Containers": containers or {}}

    def reload(self) -> None:
        return None


class FakeContainers:
    def __init__(self) -> None:
        self.created: list[FakeContainer] = []
        self.calls: list[str] = []
        self.removed = 0
        self.next: dict[str, Any] = {}
        self.listing: list[FakeContainer] = []
        self.list_filters: dict[str, Any] | None = None

    def create(self, **kwargs: Any) -> FakeContainer:
        self.calls.append("create")
        c = FakeContainer(self, kwargs, **self.next)
        self.created.append(c)
        return c

    def list(self, **kw: Any) -> list[FakeContainer]:
        self.list_filters = kw.get("filters")
        return self.listing


class FakeNetworks:
    def __init__(self, nets: dict[str, FakeNetwork]) -> None:
        self.nets = nets

    def get(self, name: str) -> FakeNetwork:
        if name not in self.nets:
            raise LookupError(name)
        return self.nets[name]

    def create(self, name: str, **kwargs: Any) -> FakeNetwork:
        self.created = getattr(self, "created", [])
        self.created.append((name, kwargs))
        self.nets[name] = FakeNetwork()
        return self.nets[name]


class FakeDocker:
    def __init__(self, nets: dict[str, FakeNetwork] | None = None) -> None:
        self.containers = FakeContainers()
        self.networks = FakeNetworks(nets if nets is not None else {"offensive": FakeNetwork(), "none": FakeNetwork()})


@pytest.fixture
def docker() -> FakeDocker:
    return FakeDocker()


# ---------------------------------------------------------------------- throwaway PKI
def _name(cn: str) -> Any:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn: str = "test-ca") -> tuple[Any, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(ca: tuple[Any, Any], cn: str, *, dns: tuple[str, ...] = ("localhost",)) -> tuple[Any, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sans: list[Any] = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    cert = (
        x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca[1].subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca[0], hashes.SHA256())
    )
    return key, cert


def write_pair(directory: Path, name: str, pair: tuple[Any, Any]) -> tuple[Path, Path]:
    from cryptography.hazmat.primitives import serialization

    crt, key = directory / f"{name}.crt", directory / f"{name}.key"
    crt.write_bytes(pair[1].public_bytes(serialization.Encoding.PEM))
    key.write_bytes(pair[0].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return crt, key


def write_ca(directory: Path, ca: tuple[Any, Any], name: str = "ca") -> Path:
    from cryptography.hazmat.primitives import serialization

    path = directory / f"{name}.crt"
    path.write_bytes(ca[1].public_bytes(serialization.Encoding.PEM))
    return path


@pytest.fixture
def pki(tmp_path: Path) -> dict[str, Any]:
    d = tmp_path / "pki"
    d.mkdir()
    ca = make_ca()
    write_ca(d, ca)
    write_pair(d, "errow-mcp", make_leaf(ca, "errow-mcp", dns=("errow-mcp", "localhost")))
    other = make_ca("other-ca")
    return {"dir": d, "ca": ca, "other": other, "tmp": tmp_path}
