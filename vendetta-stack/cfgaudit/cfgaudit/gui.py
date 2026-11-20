#!/usr/bin/env python3
"""Optional Tkinter GUI; the CLI and adapter do not import Tkinter."""
import os
import queue
import sys
import threading

from . import engine as cfgaudit

SEV_COLORS = {"Critical": "#b00020", "High": "#e65100", "Medium": "#b8860b", "Low": "#558b2f", "Info": "#546e7a"}


def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("cfgaudit - network configuration auditor")
    root.geometry("1100x720")
    files, results = [], {}
    finding_rows = {}                      # tree item id -> Finding

    # ---- file selection
    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")
    ttk.Label(top, text="Config files").grid(row=0, column=0, sticky="w")
    lb = tk.Listbox(top, height=5, selectmode="extended")
    lb.grid(row=1, column=0, rowspan=4, sticky="ew", padx=(0, 8))
    top.columnconfigure(0, weight=1)

    def add_files():
        for p in filedialog.askopenfilenames(title="Select configuration files"):
            if p not in files:
                files.append(p); lb.insert("end", p)

    def add_folder():
        d = filedialog.askdirectory(title="Select a folder of configuration files")
        for base, _, names in os.walk(d) if d else []:
            for n in sorted(names):
                p = os.path.join(base, n)
                if p not in files and os.path.getsize(p) < 20_000_000:
                    files.append(p); lb.insert("end", p)

    def remove_sel():
        for i in reversed(lb.curselection()):
            lb.delete(i); files.pop(i)

    ttk.Button(top, text="Add files...", command=add_files).grid(row=1, column=1, sticky="ew")
    ttk.Button(top, text="Add folder...", command=add_folder).grid(row=2, column=1, sticky="ew")
    ttk.Button(top, text="Remove selected", command=remove_sel).grid(row=3, column=1, sticky="ew")

    # ---- options
    opt = ttk.Frame(root, padding=(8, 0))
    opt.pack(fill="x")
    sev_v, shd_v, host_v = tk.StringVar(value="Info"), tk.StringVar(value="native"), tk.StringVar(value="localhost")
    ttk.Label(opt, text="Minimum severity").pack(side="left")
    ttk.Combobox(opt, textvariable=sev_v, values=list(cfgaudit.SEV), width=9, state="readonly").pack(side="left", padx=6)
    ttk.Label(opt, text="Shadowing").pack(side="left", padx=(12, 0))
    ttk.Combobox(opt, textvariable=shd_v, values=["native", "off", "batfish", "both"], width=9,
                 state="readonly").pack(side="left", padx=6)
    ttk.Label(opt, text="Batfish host").pack(side="left", padx=(12, 0))
    ttk.Entry(opt, textvariable=host_v, width=16).pack(side="left", padx=6)
    run_btn = ttk.Button(opt, text="Run audit")
    run_btn.pack(side="right")
    status = tk.StringVar(value="Add configuration files, then press Run audit.")
    ttk.Label(root, textvariable=status, padding=(8, 4)).pack(fill="x")

    # ---- results
    pane = ttk.PanedWindow(root, orient="vertical")
    pane.pack(fill="both", expand=True, padx=8, pady=4)
    tree = ttk.Treeview(pane, columns=("sev", "dev", "id", "title"), show="headings", height=14)
    for c, t, w in (("sev", "Severity", 80), ("dev", "Device", 140), ("id", "Rule", 80), ("title", "Finding", 700)):
        tree.heading(c, text=t); tree.column(c, width=w, anchor="w")
    for k, col in SEV_COLORS.items():
        tree.tag_configure(k, foreground=col)
    sb = ttk.Scrollbar(tree, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set); sb.pack(side="right", fill="y")
    pane.add(tree, weight=3)
    detail = tk.Text(pane, height=10, wrap="word", state="disabled")
    pane.add(detail, weight=2)

    def show_detail(_=None):
        sel = tree.selection()
        if not sel:
            return
        f = finding_rows[sel[0]]
        lines = [f"{f.rule_id}  [{f.severity}]  {f.title}", f"Device: {f.device} ({f.vendor})", "", "Evidence:"]
        lines += [f"  {e}" for e in f.evidence]
        lines += ["", f"Fix: {f.remediation}"]
        if f.refs:
            lines += ["", "References:"] + [f"  {k}: {v}" for k, v in f.refs.items()]
        detail.configure(state="normal"); detail.delete("1.0", "end")
        detail.insert("1.0", "\n".join(lines)); detail.configure(state="disabled")

    tree.bind("<<TreeviewSelect>>", show_detail)

    # ---- run (background thread keeps the window responsive)
    def finish(res, warns):
        nonlocal results
        results = res
        tree.delete(*tree.get_children()); finding_rows.clear()
        for dev, fs in res.items():
            for f in fs:
                iid = tree.insert("", "end", values=(f.severity, dev, f.rule_id, f.title), tags=(f.severity,))
                finding_rows[iid] = f
        s = cfgaudit.summarize(res)
        msg = f"{len(res)} device(s): " + ", ".join(f"{k} {v}" for k, v in reversed(list(s.items())) if v)
        status.set(msg + (f"   |   {len(warns)} warning(s): {warns[0]}" if warns else ""))
        run_btn.configure(state="normal")

    q = queue.Queue()

    def poll():                                    # Tk is only touched from the main thread
        try:
            res, warns = q.get_nowait()
        except queue.Empty:
            root.after(100, poll); return
        finish(res, warns)

    def run():
        if not files:
            messagebox.showinfo("cfgaudit", "Add at least one configuration file first."); return
        run_btn.configure(state="disabled"); status.set("Running...")
        args = (list(files), None, sev_v.get(), shd_v.get(), host_v.get())

        def work():
            try:
                q.put(cfgaudit.run_audit(*args))
            except Exception as ex:                # surface unexpected parser errors in the UI
                q.put(({}, [f"{type(ex).__name__}: {ex}"]))
        threading.Thread(target=work, daemon=True).start()
        root.after(100, poll)

    run_btn.configure(command=run)

    # ---- export
    def export():
        if not results:
            messagebox.showinfo("cfgaudit", "Run an audit first."); return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[
            ("HTML report", "*.html"), ("JSON", "*.json"), ("Text", "*.txt")])
        if p:
            fmt = {"html": "html", "json": "json"}.get(p.rsplit(".", 1)[-1].lower(), "text")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(cfgaudit.render(results, fmt))
            status.set(f"Report saved to {p}")

    ttk.Button(root, text="Export report...", command=export).pack(anchor="e", padx=8, pady=(0, 8))
    root.mainloop()


def main():
    args = sys.argv[1:]
    if not args or args == ["--gui"]:
        try:
            gui()
        except ImportError:
            print("The GUI needs tkinter (not available in this Python). Use the CLI: cfgaudit --help",
                  file=sys.stderr)
            return 1
        return 0
    return cfgaudit.main(args)


if __name__ == "__main__":
    sys.exit(main())
