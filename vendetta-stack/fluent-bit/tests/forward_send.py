#!/usr/bin/env python3
"""Traces: PROMPT §4 Phase 4 (validation). Test-only Fluent Forward client (stdlib only): sends one Message-mode event
[tag, time, record] with a hand-rolled msgpack encoder (str/int/float/bool/None/list/dict).
Usage: forward_send.py <host> <port> <tag> '<json record>' [--tls CA CRT|- KEY|- SERVERNAME]   (`-` = present no client certificate)
"""
import json
import socket
import ssl
import struct
import sys
import time


def pack(obj):
    if obj is None:
        return b"\xc0"
    if obj is True:
        return b"\xc3"
    if obj is False:
        return b"\xc2"
    if isinstance(obj, int):
        if 0 <= obj < 128:
            return bytes([obj])
        return b"\xd3" + struct.pack(">q", obj)
    if isinstance(obj, float):
        return b"\xcb" + struct.pack(">d", obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return b"\xdb" + struct.pack(">I", len(raw)) + raw
    if isinstance(obj, list):
        return b"\xdd" + struct.pack(">I", len(obj)) + b"".join(pack(x) for x in obj)
    if isinstance(obj, dict):
        out = b"\xdf" + struct.pack(">I", len(obj))
        for key, value in obj.items():
            out += pack(str(key)) + pack(value)
        return out
    raise TypeError(type(obj))


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    host, port, tag, record = sys.argv[1], int(sys.argv[2]), sys.argv[3], json.loads(sys.argv[4])
    sock = socket.create_connection((host, port), timeout=10)
    if len(sys.argv) >= 6 and sys.argv[5] == "--tls":
        ca, crt, key, name = sys.argv[6:10]
        ctx = ssl.create_default_context(cafile=ca)
        if crt != "-":
            ctx.load_cert_chain(crt, key)
        sock = ctx.wrap_socket(sock, server_hostname=name)
    sock.sendall(pack([tag, int(time.time()), record]))
    time.sleep(0.5)
    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
