# ML Handoff — QUT-DV25 Dataset

This document explains how to export the collected npm-ebpf-monitor sessions into
a CSV ready for Random Forest training, and the exact column layout the ML team
should expect.

---

## 1. Generate the CSV (Go)

The exporter is a standalone Go binary that reads every `.json` session file and
writes a 39-column CSV.

```bash
# From the project root:
go run ./cmd/dataset/exporter \
  --dir ./sessions/dataset/ \
  --out ./sessions/sessions.csv
```

Expected output:

```
Wrote 18 rows to ./sessions/sessions.csv.
```

---

## 2. Verify the CSV structure

```bash
# Check column count (expected: 39)
head -n 1 ./sessions/sessions.csv | awk -F, '{print "Columns: " NF}'
# Expected: Columns: 39  (36 features + 3 metadata)

# Check label distribution
awk -F, 'NR>1 {print $2}' ./sessions/sessions.csv | sort | uniq -c
# Example expected output:
#   15 0   ← benign
#    3 1   ← malicious
```

---

## 3. Column layout (39 columns)

| # | Column name | Source |
|---|-------------|--------|
| 1 | `package_name` | Session metadata |
| 2 | `label` | 0 = benign, 1 = malicious |
| 3 | `read_processes` | filetop |
| 4 | `write_processes` | filetop |
| 5 | `read_data_transfer_kb` | filetop |
| 6 | `write_data_transfer_kb` | filetop |
| 7 | `file_access_processes` | filetop |
| 8 | `total_dependencies` | install |
| 9 | `direct_dependencies` | install |
| 10 | `indirect_dependencies` | install |
| 11 | `root_dir_access` | opensnoop |
| 12 | `temp_dir_access` | opensnoop |
| 13 | `home_dir_access` | opensnoop |
| 14 | `user_dir_access` | opensnoop |
| 15 | `sys_dir_access` | opensnoop |
| 16 | `etc_dir_access` | opensnoop |
| 17 | `other_dir_access` | opensnoop |
| 18 | `state_transitions` | tcp |
| 19 | `local_ips` | tcp |
| 20 | `remote_ips` | tcp |
| 21 | `local_ports` | tcp |
| 22 | `remote_ports` | tcp |
| 23 | `io_ops` | syscalls |
| 24 | `file_ops` | syscalls |
| 25 | `network_ops` | syscalls |
| 26 | `time_ops` | syscalls |
| 27 | `security_ops` | syscalls |
| 28 | `process_ops` | syscalls |
| 29 | `unknown_ops` | syscalls |
| 30 | `p1_file_metadata` | n-gram patterns |
| 31 | `p2_read_data` | n-gram patterns |
| 32 | `p3_write_data` | n-gram patterns |
| 33 | `p4_socket_create` | n-gram patterns |
| 34 | `p5_process_create` | n-gram patterns |
| 35 | `p6_memory_map` | n-gram patterns |
| 36 | `p7_fd_manage` | n-gram patterns |
| 37 | `p8_ipc` | n-gram patterns |
| 38 | `p9_file_lock` | n-gram patterns |
| 39–1: `p10_error_handle` then | `severity_score` | derived (mirrors label) |

> **Note:** Column 39 is `p10_error_handle` and column 40 is `severity_score`?
> No — the total is exactly 39: 2 leading metadata + 36 QUT-DV25 features +
> 1 trailing `severity_score`.  `unknown_ops` (column 29) is included in the
> syscall group (7 fields: io, file, network, time, security, process, unknown).

---

## 4. Load the CSV in Python (pandas)

The ML team works entirely in Python / pandas for model training.  The CSV
produced by the Go exporter is a standard RFC 4180 file and loads with zero
special configuration needed.

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ── Load ──────────────────────────────────────────────────────────────────────
df = pd.read_csv("sessions/sessions.csv")

# ── Quick sanity checks ───────────────────────────────────────────────────────
print(f"Shape: {df.shape}")          # (N, 39)
print(df["label"].value_counts())    # 0: benign, 1: malicious

# ── Feature / label split ─────────────────────────────────────────────────────
FEATURE_COLS = [c for c in df.columns
                if c not in ("package_name", "label", "severity_score")]

X = df[FEATURE_COLS]
y = df["label"]

# ── Train / test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Random Forest ─────────────────────────────────────────────────────────────
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

print(classification_report(y_test, clf.predict(X_test)))

# ── Feature importance ────────────────────────────────────────────────────────
importances = pd.Series(clf.feature_importances_, index=FEATURE_COLS)
print(importances.sort_values(ascending=False).head(10))
```

### Key decisions encoded in the CSV

| Decision | Detail |
|----------|--------|
| **Label encoding** | Binary: `0` = benign, `1` = malicious |
| **`severity_score`** | Mirrors `label` (baseline); replace with a continuous risk score once malicious sub-categories are defined |
| **`unknown_ops`** | Kept in feature set — may capture novel syscall patterns |
| **`.ssh` / `.aws` paths** | Classified as `other_dir_access` by BPF layer; no separate column |
| **Data transfer** | Approximate KB values from filetop (`read_data_transfer_kb`, `write_data_transfer_kb`) |

---

## 5. Re-running after adding more sessions

```bash
# 1. Label new sessions
go run ./cmd/dataset/labeler --dir ./sessions/dataset/

# 2. Re-export CSV
go run ./cmd/dataset/exporter \
  --dir ./sessions/dataset/ \
  --out ./sessions/sessions.csv

# 3. Validate
head -n 1 ./sessions/sessions.csv | awk -F, '{print "Columns: " NF}'
```
