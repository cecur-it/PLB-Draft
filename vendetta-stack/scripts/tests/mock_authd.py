#!/usr/bin/env python3
"""Minimal TLS stand-in for the Vendetta manager enrollment service (authd) used by scripts/tests/test_scripts.sh.

Usage: mock_authd.py --cert CRT --key KEY --password-file FILE --port-file FILE [--log FILE]

Speaks the line protocol of Wazuh-compatible authd: the client sends
    OSSEC PASS: <password> OSSEC A:'<name>' [G:'<group>'] [IP:'<ip>']
and receives
    OSSEC K:'<id> <name> <ip> <64 hex chars>'      on success
    ERROR: Invalid password                          wrong or missing password
    ERROR: Duplicated agent name: <name>             name already enrolled in this process
Only the agent name and outcome are logged, never the password.
"""
import argparse
import hashlib
import json
import re
import signal
import socketserver
import ssl
import sys
import threading

REQ = re.compile(r"^(?:OSSEC PASS: (?P<pw>\S+) )?OSSEC A:'(?P<name>[^']+)'(?: G:'(?P<group>[^']*)')?(?: IP:'(?P<ip>[^']*)')?\s*$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--port-file", required=True)
    ap.add_argument("--log", default="")
    args = ap.parse_args()
    with open(args.password_file, encoding="utf-8") as fh:
        password = fh.read().strip()
    agents = {}
    lock = threading.RLock()

    def log(entry):
        if args.log:
            with lock, open(args.log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline(4096).decode("utf-8", "replace").strip()
            m = REQ.match(line)
            if not m:
                self.wfile.write(b"ERROR: Invalid request for new agent\n")
                log({"outcome": "bad-request"})
                return
            name = m.group("name")
            if m.group("pw") != password:
                self.wfile.write(b"ERROR: Invalid password\n")
                log({"name": name, "outcome": "bad-password"})
                return
            with lock:
                if name in agents:
                    self.wfile.write(f"ERROR: Duplicated agent name: {name}\n".encode())
                    log({"name": name, "outcome": "duplicate"})
                    return
                agent_id = f"{len(agents) + 1:03d}"
                key = hashlib.sha256(f"{agent_id}:{name}".encode()).hexdigest()
                agents[name] = agent_id
            ip = m.group("ip") or "any"
            self.wfile.write(f"OSSEC K:'{agent_id} {name} {ip} {key}'\n\n".encode())
            log({"name": name, "group": m.group("group"), "ip": ip, "outcome": "enrolled"})

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = Server(("127.0.0.1", 0), Handler, bind_and_activate=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with open(args.port_file, "w", encoding="utf-8") as fh:
        fh.write(str(srv.server_address[1]))
    stop = threading.Event()
    def on_signal(*_):
        # repeated TERMs re-enter the handler through CPython's pending-call path; ignore them after the first
        if stop.is_set():
            return
        stop.set()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    # a timed wait: an untimed Event.wait() is not interrupted when the signal lands on a server thread
    while not stop.wait(0.2):
        pass
    # shutdown() joins the serve_forever loop, which can sit in accept() on the wrapped listening
    # socket; never let that block the exit (daemon threads die with the process anyway)
    t = threading.Thread(target=srv.shutdown, daemon=True)
    t.start()
    t.join(2.0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
