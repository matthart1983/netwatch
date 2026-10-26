#!/usr/bin/env bash
# Time the connection table at 2,000, 10,000 and 50,000 rows, and print the
# results as a Markdown table for docs/PERFORMANCE.md.
#
#   scripts/scale-bench.sh [table.md]
#
# Runs the scale_ tests in src/scale_tests.rs from a release build, one at a
# time. Budgets apply at 10,000 rows and are multiplied by NW_PERF_SLACK:
# 1 (the default) on the reference machine, 3 in CI. A missed budget fails
# the run, including one still Pending on the branch that should meet it,
# so a release candidate's run has to meet them all. NW_PERF_STRICT=0,
# which the perf workflow sets, prints a missed Pending budget as pending
# instead. Every test runs and the table is printed even when one fails,
# and the script then exits nonzero. The real-socket poll opens up to
# 50,000 loopback sockets, so the open-file limit is raised to the hard limit
# first, and it lists every socket on the host, so run it on a quiet one.
# With table.md given, the table is also written there and the test output
# to table.log.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-}"
if [ -n "${out}" ]; then
    log="${out%.md}.log"
else
    log=$(mktemp)
    trap 'rm -f "${log}"' EXIT
fi

ulimit -n "$(ulimit -Hn)" 2>/dev/null || ulimit -n 65536 2>/dev/null || true
export NW_PERF_SLACK="${NW_PERF_SLACK:-1}"

status=0
cargo nextest run --release --run-ignored only --no-fail-fast -E 'test(/scale_/)' --no-capture 2>&1 |
    tee "${log}" || status=$?

cpu=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -n 1 || true)
mem=$(awk '/^MemTotal:/ { printf "%.0f GB", $2 / 1048576 }' /proc/meminfo 2>/dev/null || true)

table() {
    echo "Commit $(git rev-parse --short HEAD), $(date -u +%Y-%m-%d), NW_PERF_SLACK=${NW_PERF_SLACK}."
    echo "${cpu:-$(uname -m)}, $(getconf _NPROCESSORS_ONLN) threads${mem:+, ${mem}}, $(uname -sr), $(rustc --version)."
    echo
    # One `SCALE key=value ...` line per case and size; see Report::record.
    awk '
        function commas(n) {
            while (n ~ /[0-9][0-9][0-9][0-9]/) sub(/[0-9][0-9][0-9]($|,)/, ",&", n)
            return n
        }
        /^SCALE / {
            split("", f)
            for (i = 2; i <= NF; i++) {
                eq = index($i, "=")
                f[substr($i, 1, eq - 1)] = substr($i, eq + 1)
            }
            c = f["case"]; n = f["rows"]
            if (!(c in seen)) { seen[c] = 1; cases[++ncases] = c }
            if (!(n in seen_rows)) { seen_rows[n] = 1; sizes[++nsizes] = n }
            cell[c, n] = f["p50_ms"] " / " f["p99_ms"]
            if (f["status"] != "unjudged") {
                b = f["budget"]; sub(/<=/, " ≤ ", b); sub(/ms$/, " ms", b)
                s = f["status"]
                if ("owner" in f) s = s " (" f["owner"] ")"
                judged[c] = b ", " s
            }
        }
        END {
            if (ncases == 0) exit
            head = "| Case, ms p50 / p99 |"; rule = "|---|"
            for (j = 1; j <= nsizes; j++) { head = head " " commas(sizes[j]) " rows |"; rule = rule "---:|" }
            print head " Budget at 10,000 rows |"
            print rule "---|"
            for (i = 1; i <= ncases; i++) {
                c = cases[i]; line = "| " c " |"
                for (j = 1; j <= nsizes; j++) {
                    v = ((c, sizes[j]) in cell) ? cell[c, sizes[j]] : "-"
                    line = line " " v " |"
                }
                print line " " ((c in judged) ? judged[c] : "-") " |"
            }
        }
    ' "${log}"
}

echo
if [ -n "${out}" ]; then
    table | tee "${out}"
else
    table
fi
exit "${status}"
