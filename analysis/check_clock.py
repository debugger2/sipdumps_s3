# -*- coding: utf-8 -*-
import json, os, statistics, collections
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sip_index.json")
recs = json.load(open(p, encoding="utf-8"))
fs = [r for r in recs if "_fs" in r["file"]]
klb = [r for r in recs if "_klb" in r["file"]]
# match by (call_id, cseq_num, method)
def key(r):
    return (r["call_id"], r["cseq"].split(" ")[0], r["method"])
fsmap = collections.defaultdict(list)
for r in fs: fsmap[key(r)].append(r)
diffs = []
for r in klb:
    if not r["method"]: continue
    lst = fsmap.get(key(r))
    if not lst: continue
    # первый INVITE в fs (до klb-пакета с запасом)
    cands = [x for x in lst if x["ts"] <= r["ts"] + 5]
    if not cands: cands = lst
    a = max(cands, key=lambda x: x["ts"])
    diffs.append(r["ts"] - a["ts"])
print("matched pairs:", len(diffs))
if diffs:
    diffs.sort()
    print("min/median/max diff (klb - fs): %.6f / %.6f / %.6f s" % (diffs[0], statistics.median(diffs), diffs[-1]))
    print("p10/p90: %.6f / %.6f" % (diffs[len(diffs)//10], diffs[len(diffs)*9//10]))
    print("samples:", ["%.3f" % d for d in diffs[:20]])
