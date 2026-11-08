"""Miss rate of random credential values through the scanner, one file per value.

Usage: python3 eval/random_value_miss_rate.py <riskgrep binary> <scratch dir> <values per case> <stopword list>
(for example: target/release/riskgrep /tmp/miss 8000
crates/riskgrep-core/rulesets/secrets-core/stopwords/secrets_core_generic_api_key.txt).
For 32, 40, and 64 hex digits and 40 letters and digits, writes <values> files per
layout (XML element, credential-named JSON object, api_key line), scans each
layout directory with --no-cache, and counts files whose secret score is below 80,
by cause. Values are random and never printed; `limits.walk_files` (10000) caps a
directory, so <values> must stay below it.
"""
import json, math, os, secrets, shutil, subprocess, sys, string
from collections import Counter

BIN = sys.argv[1]
OUT = sys.argv[2]
N = int(sys.argv[3])
WORDS = sys.argv[4]

def entropy(s):
    return -sum(n / len(s) * math.log2(n / len(s)) for n in Counter(s).values())

def hexv(n):
    return secrets.token_hex(n // 2)

def alnum(n):
    a = string.ascii_letters + string.digits
    return "".join(secrets.choice(a) for _ in range(n))

LAYOUTS = {
    "xml": ("x{}.xml", "<Config><ApiKey>{}</ApiKey></Config>\n"),
    "json": ("x{}.json", '{{"apiKeys": {{"primary": "{}"}}}}\n'),
    "conf": ("x{}.conf", "api_key = {}\n"),
}
CASES = [("hex32", lambda: hexv(32)), ("hex40", lambda: hexv(40)), ("hex64", lambda: hexv(64)), ("alnum40", lambda: alnum(40))]

shutil.rmtree(OUT, ignore_errors=True)
meta = {}
for cname, gen in CASES:
    for lname, (fname, tmpl) in LAYOUTS.items():
        d = os.path.join(OUT, cname, lname)
        os.makedirs(d)
        for i in range(N):
            v = gen()
            with open(os.path.join(d, fname.format(i)), "w") as f:
                f.write(tmpl.format(v))
            meta[os.path.join(cname, lname, fname.format(i))] = v
targets = []
for cname, _ in CASES:
    for lname in LAYOUTS:
        res = subprocess.run([BIN, "scan", "--no-cache", "--format", "json", os.path.join(OUT, cname, lname)], capture_output=True, text=True)
        d = json.loads(res.stdout)
        assert d["summary"]["unscanned"] == 0 and d["summary"]["scanned"] == N, d["summary"]
        targets += d["targets"]
data = {"targets": targets}
words = [w.strip().lower() for w in open(WORDS) if w.strip()]
root = os.path.abspath(OUT)
missed = {}
seen = 0
for t in data["targets"]:
    rel = os.path.relpath(t["target"], root)
    seen += 1
    if t["scores"].get("secret", 0) < 80:
        missed[rel] = t["scores"].get("secret", 0)
assert seen == len(meta), (seen, len(meta))
from collections import defaultdict
tab = defaultdict(lambda: defaultdict(int))
for cname, _ in CASES:
    for lname in LAYOUTS:
        tab[(cname, lname)]["total"] = N
for rel in missed:
    v = meta[rel]
    cname, lname, _ = rel.split(os.sep)
    low = v.lower()
    cause = []
    if any(w in low for w in words): cause.append("stopword")
    if entropy(v) < 3.0: cause.append("entropy<3.0")
    if not any(c.isdigit() for c in v) or not any(c.isalpha() for c in v): cause.append("no digit/letter")
    if any(r in low for r in ("0123456", "123456789", "abcdef", "fedcba")): cause.append("sequential run")
    if not cause: cause.append("other")
    k = tab[(cname, lname)]
    k["missed"] += 1
    for c in cause: k[c] += 1
for (cname, lname), k in sorted(tab.items()):
    print(cname, lname, "values", k["total"], "missed", k["missed"], {x: y for x, y in k.items() if x not in ("total", "missed")})
