#!/usr/bin/env bash
#
# ab-run.sh -- run the autobahn fuzzingclient suite in parallel shards.
#
# Goal: cut a full 517-case autobahn run from several minutes down to ~1-2 min
# by slicing the case list and launching N `wstest` containers at once, each
# with its own config + outdir, then merging the per-shard report/index.json.
#
# Usage:
#   ab-run.sh [config-name] [shards]
#
#   config-name : basename of autobahn/config/<name>.json (default: fuzzingclient-io)
#                 e.g. fuzzingclient-io, fuzzingclient-onebyone, fuzzingclient-elastic,
#                      fuzzingclient-no-context-takeover-decompression, ...
#   shards      : number of parallel wstest processes (default: 8)
#
# Env overrides:
#   AB_CONFIG_DIR  (default ~/fio/autobahn/config)
#   AB_REPORT_DIR  (default /root/abreport)        # merged result -> index.json here
#   AB_REPORT_FILE (default $AB_REPORT_DIR/index.json)
#   AB_IMAGE       (default crossbario/autobahn-testsuite)
#   AB_LOCK        (default /tmp/lab-heavy.lock)   # flock, shared with the perf line
#   AB_NOLOCK=1    skip flock (NOT recommended while the perf agent is active)
#   AB_ARGS        extra args appended to every `wstest` invocation
#   AB_KEEP=1      keep per-shard work dirs + logs (default: cleaned)
#
# Run as root (docker). Exit: 0 zero FAILED, 1 any FAILED, 2 setup error.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
CONFIG_NAME="${1:-fuzzingclient-io}"
SHARDS="${2:-8}"

AB_CONFIG_DIR="${AB_CONFIG_DIR:-$HOME/fio/autobahn/config}"
AB_REPORT_DIR="${AB_REPORT_DIR:-/root/abreport}"
AB_REPORT_FILE="${AB_REPORT_FILE:-$AB_REPORT_DIR/index.json}"
AB_IMAGE="${AB_IMAGE:-crossbario/autobahn-testsuite}"
AB_LOCK="${AB_LOCK:-/tmp/lab-heavy.lock}"
AB_ARGS="${AB_ARGS:-}"
AB_PYPY="${AB_PYPY:-/opt/pypy/bin/pypy}"

if [ ! -f "$AB_CONFIG_DIR/$CONFIG_NAME.json" ]; then
	for d in "$HERE/../autobahn/config" "$HERE/autobahn/config" "$HOME/fio/autobahn/config"; do
		if [ -f "$d/$CONFIG_NAME.json" ]; then AB_CONFIG_DIR="$d"; break; fi
	done
fi
SRC_CONFIG="$AB_CONFIG_DIR/$CONFIG_NAME.json"
[ -f "$SRC_CONFIG" ] || { echo "ab-run: no such config: $SRC_CONFIG" >&2; exit 2; }

WORK="/tmp/ab-run-$$"
mkdir -p "$WORK"

# 1. Enumerate the case universe + build balanced shard configs ---------------
# The case universe is fixed (517 cases), so enumerate it once from the
# testsuite and cache it; sharding is a pure function of the config.
CASES_CACHE=/tmp/ab-cases.json
if [ ! -s "$CASES_CACHE" ]; then
	docker run --rm --entrypoint "$AB_PYPY" "$AB_IMAGE" -c '
import json
from autobahntestsuite.case import Cases, CaseBasename
l = len(CaseBasename)
print(json.dumps([".".join(c.__name__[l:].split("_")) for c in Cases]))
' > "$CASES_CACHE" || { echo "ab-run: case enumeration failed" >&2; exit 2; }
fi

python3 - "$SRC_CONFIG" "$SHARDS" "$WORK" "$CASES_CACHE" <<'PY'
import json, os, sys

src, nshards, work, cache = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
cfg = json.load(open(src))
universe = json.load(open(cache))

# Respect the source config's own case selection: autobahn matches a case
# against the config's "cases" glob list (any match) then drops anything in
# "exclude-cases". We reproduce that here so a filtered config (e.g.
# ["12.3.*"]) shards only its own subset.
import fnmatch
def matches(case, pat):
    return fnmatch.fnmatchcase(case, pat)
sel = cfg.get("cases") or ["*"]
exc = [e for e in (cfg.get("exclude-cases") or []) if e]
allcases = [c for c in universe
            if any(matches(c, p) for p in sel) and not any(matches(c, e) for e in exc)]

# Shard by *unit* = first two dotted components ("6.4" of "6.4.2"); fall back
# to the first component for 2-part ids ("2.5"). Units keep whole semantic
# groups together (e.g. all compression cases in "13.7") while letting the big
# groups 6/9/12/13 spread across shards.
def unit(c):
    p = c.split(".")
    return ".".join(p[:2]) if len(p) >= 2 else p[0]

groups = {}
for c in allcases:
    groups.setdefault(unit(c), []).append(c)

# bin-pack units (largest first) onto shards to balance total case count
order = sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)
bins = [[] for _ in range(nshards)]
counts = [0] * nshards
for u, cs in order:
    i = min(range(nshards), key=lambda j: counts[j])
    bins[i].extend(cs)
    counts[i] += len(cs)

tmpl = dict(cfg)
manifests = []
for i, b in enumerate(bins):
    if not b:
        continue
    outdir = os.path.join(work, "shard%d" % i)
    os.makedirs(outdir, exist_ok=True)
    c = json.loads(json.dumps(tmpl))
    c["cases"] = sorted(b, key=lambda s: [int(x) for x in s.split(".")])
    # outdir is the *container-side* path; the host shard dir is bind-mounted
    # at /report, mirroring how the repo configs + docker run work.
    c["outdir"] = "/report/"
    c["exclude-cases"] = []
    cfgpath = os.path.join(work, "cfg%d.json" % i)
    json.dump(c, open(cfgpath, "w"), indent=2)
    manifests.append({"cfg": cfgpath, "outdir": outdir, "n": len(b)})

json.dump(manifests, open(os.path.join(work, "manifest.json"), "w"))
print("ab-run: %d cases over %d shards: %s" %
      (len(allcases), len(manifests), ",".join(str(m["n"]) for m in manifests)))
PY
[ -s "$WORK/manifest.json" ] || { echo "ab-run: shard generation failed" >&2; exit 2; }

rm -rf "$AB_REPORT_DIR"
mkdir -p "$AB_REPORT_DIR"

# 2. Run the shards in parallel under the shared heavy lock -------------------
cat > "$WORK/run_impl.sh" <<EOF
#!/usr/bin/env bash
WORK='$WORK'; AB_IMAGE='$AB_IMAGE'; AB_ARGS='$AB_ARGS'; AB_PYPY='$AB_PYPY'
run_shards() {
  i=0
  while read -r m; do
    cfg=\$(echo "\$m" | python3 -c 'import sys,json;print(json.load(sys.stdin)["cfg"])')
    out=\$(echo "\$m" | python3 -c 'import sys,json;print(json.load(sys.stdin)["outdir"])')
    ( docker run --rm --net=host -v "\$WORK:/config" -v "\$out:/report" \\
        "\$AB_IMAGE" wstest -m fuzzingclient -s "/config/\$(basename "\$cfg")" \$AB_ARGS \\
        > "\$WORK/shard\$i.log" 2>&1; echo \$? > "\$WORK/shard\$i.rc" ) &
    i=\$((i+1))
  done < <(python3 -c 'import json,sys;[print(json.dumps(m)) for m in json.load(open(sys.argv[1]))]' "\$WORK/manifest.json")
  wait
}
run_shards
EOF
chmod +x "$WORK/run_impl.sh"

if [ "${AB_NOLOCK:-0}" = "1" ]; then
	"$WORK/run_impl.sh"
else
	flock "$AB_LOCK" "$WORK/run_impl.sh"
fi

# 3. Merge per-shard reports -------------------------------------------------
python3 - "$WORK" "$AB_REPORT_FILE" <<'PY'
import json, os, sys, glob
work, out = sys.argv[1], sys.argv[2]
merged, n = {}, 0
for idx in glob.glob(os.path.join(work, "shard*", "index.json")):
    for agent, cases in json.load(open(idx)).items():
        m = merged.setdefault(agent, {})
        for k, v in cases.items():
            if k in m and m[k].get("behavior") != v.get("behavior"):
                sys.stderr.write("ab-run: WARNING %s/%s differs across shards\n" % (agent, k))
            m[k] = v
    n += 1
os.makedirs(os.path.dirname(out), exist_ok=True)
json.dump(merged, open(out, "w"))
print("ab-run: merged %d shard report(s) -> %s" % (n, out))
PY

# 4. Summarize ---------------------------------------------------------------
python3 - "$AB_REPORT_FILE" <<'PY'
import json, sys
from collections import Counter
d = json.load(open(sys.argv[1]))
total, fail = Counter(), []
for agent, cases in sorted(d.items()):
    c = Counter()
    for k, v in cases.items():
        b, bc = v.get("behavior"), v.get("behaviorClose")
        c[b] += 1; c[bc] += 1; total[b] += 1; total[bc] += 1
        if b == "FAILED" or bc == "FAILED":
            fail.append((agent, k, b, bc))
    print("== %-56s %d cases" % (agent, len(cases)))
    print("     " + ", ".join("%s(b/bc)=%d" % (s, n) for s, n in sorted(c.items())))
print("== TOTAL (%d agents) ==" % len(d))
for st in ("OK", "NON-STRICT", "INFORMATIONAL", "FAILED"):
    if total.get(st):
        print("     %-14s %d" % (st, total[st]))
if fail:
    print("\nFAILED cases:")
    for a, k, b, bc in sorted(fail):
        print("  %s %-12s behavior=%s close=%s" % (a, k, b, bc))
    sys.exit(1)
print("\nno FAILED cases")
PY
RC=$?

if [ "${AB_KEEP:-0}" != "1" ]; then rm -rf "$WORK"; fi
exit $RC
