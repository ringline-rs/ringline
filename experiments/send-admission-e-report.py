#!/usr/bin/env python3
"""Summarise Experiment E's runs with send-admission-d-report.py.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run of send-admission-e.toml. The report is D's, with two changes:

- tls is a cell key, so TLS and plaintext runs of a workload are separate
  cells, and each gated arm is compared with the O0 whole arm of its own
  transport, in the tables, U's cost, the decision rule and the prediction's
  refutation conditions;
- order `budget` is named O7w, as in the runtime (SendAdmissionOrder::Budget
  admits a passing waiter only from a connection with nothing queued).
"""

import importlib.util
import pathlib

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("d", here / "send-admission-d-report.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

d.CELL_KEYS = ("tls",) + d.CELL_KEYS
d.ORDERS["budget"] = "O7w"

if __name__ == "__main__":
    d.main()
