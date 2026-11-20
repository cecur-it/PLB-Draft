"""Optional Batfish backend for filter-line reachability (shadowing).

Needs a running Batfish service (e.g. docker run -p 9996:9996 batfish/allinone)
and `pip install pybatfish`. Uses the filterLineReachability question.
"""
import os
import shutil
import tempfile
from pathlib import Path

def rows_from_frame(rows):
    """Normalise filterLineReachability rows (list of dicts) for cfgaudit."""
    out = []
    for r in rows:
        src = r["Sources"]
        src = src[0] if isinstance(src, (list, tuple)) and src else str(src)
        node, _, filt = src.partition(": ")
        out.append({
            "node": node, "filter": filt,
            "line": r["Unreachable_Line"],
            "action": str(r["Unreachable_Line_Action"]).lower(),
            "blockers": list(r.get("Blocking_Lines") or []),
            "different_action": bool(r.get("Different_Action")),
            "reason": r.get("Reason"),
            "info": r.get("Additional_Info"),
        })
    return out

def run(paths, host="localhost", network="cfgaudit"):
    from pybatfish.client.session import Session   # imported lazily: optional dependency
    tmp = tempfile.mkdtemp(prefix="cfgaudit_bf_")
    try:
        cfgdir = Path(tmp) / "configs"
        cfgdir.mkdir()
        for p in paths:
            shutil.copy(p, cfgdir / Path(p).name)
        bf = Session(host=host)
        bf.set_network(network)
        bf.init_snapshot(tmp, name="snapshot", overwrite=True)
        frame = bf.q.filterLineReachability().answer().frame()
        return rows_from_frame(frame.to_dict("records"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
