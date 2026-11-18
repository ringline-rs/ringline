#!/usr/bin/env python3
"""Summarise Experiment E's runs with send-admission-d-report.py.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run of send-admission-e.toml. The report is D's, with three changes:

- tls is a cell key, so TLS and plaintext runs of a workload are separate
  cells, and each gated arm is compared with the O0 whole arm of its own
  transport, in the tables and the prediction's refutation conditions;
- U's cost and the decision rule run once per transport, over that
  transport's cells only, so an arm that ran over TLS alone is judged on the
  TLS cells, and the CPU ratio named with the decision is its own
  transport's;
- order `budget` is named O7w, as in the runtime (SendAdmissionOrder::Budget
  admits a passing waiter only from a connection with nothing queued).
"""

import contextlib
import importlib.util
import io
import pathlib

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("d", here / "send-admission-d-report.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

d.CELL_KEYS = ("tls",) + d.CELL_KEYS
d.ORDERS["budget"] = "O7w"

_u_cost, _decision = d.u_cost, d.decision
TRANSPORTS = ("off", "on")


def by_tls(by_cell, tls):
    return {c: v for c, v in by_cell.items() if dict(c)["tls"] == tls}


def u_cost(by_cell):
    return {t: _u_cost(by_tls(by_cell, t)) for t in TRANSPORTS}


def decision(by_cell, ratios, pressured, no_figure):
    for t in TRANSPORTS:
        print(f"\n-- decision, tls={t}")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _decision(by_tls(by_cell, t), ratios[t], pressured, no_figure)
        # D's fallback names plaintext; for each transport it is that
        # transport's own.
        print(out.getvalue().replace(
            "Experiment C's outcome stands for plaintext",
            f"Experiment C's outcome stands for tls={t}",
        ), end="")


# main() looks these names up when it runs.
d.u_cost, d.decision = u_cost, decision

if __name__ == "__main__":
    d.main()
