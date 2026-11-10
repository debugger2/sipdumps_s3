# -*- coding: utf-8 -*-
import json, os, collections, re
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sip_index.json")
recs = json.load(open(p, encoding="utf-8"))

calls = collections.OrderedDict()
for r in recs:
    cid = r["call_id"]
    if not cid: continue
    c = calls.setdefault(cid, dict(call_id=cid, files=set(), msgs=[], has181=False, has178=False,
                                   xicc="", answered=False, times=[], invite_idx=None))
    c["files"].add(r["file"]); c["msgs"].append(r); c["times"].append(r["ts"])
    if r.get("has181"): c["has181"] = True
    if r.get("has178"): c["has178"] = True
    if r["method"] == "INVITE" and r["xicc"] and not c["xicc"]:
        c["xicc"] = r["xicc"]
    if r["status"] == "200" and r["cseq"].upper().endswith("INVITE"):
        c["answered"] = True

# операторский признак: в диалоге встречается .181 (klb leg) или SDP c=.178
ops = [c for c in calls.values() if (c["has181"] or c["has178"])]
print("total dialogs:", len(calls))
print("dialogs mentioning .181/.178:", len(ops))
print("  of them answered:", sum(1 for c in ops if c["answered"]))
print("  with X-icc_uuid:", sum(1 for c in ops if c["xicc"]))

# сколько из них есть в klb-файлах
klb_cids = set(r["call_id"] for r in recs if "klb" in r["file"])
print("call-ids in klb files:", len(klb_cids))
print("klb cids also in fs dumps:", sum(1 for c in klb_cids if c in calls and any("fs" in f for f in calls[c]["files"])))

print("\n--- answered operator dialogs (candidate) ---")
for c in sorted(ops, key=lambda x: min(x["times"])):
    if not c["answered"]: continue
    import datetime
    t0 = datetime.datetime.utcfromtimestamp(min(c["times"]))
    sdpc = set()
    for m in c["msgs"]:
        sdpc.update(m.get("sdp_c", []))
    print("%s  %s  files=%s  xicc=%s  media=%s  dur=%.0fs  nmsg=%d" % (
        t0.strftime("%H:%M:%S"), c["call_id"][:18], ",".join(sorted(f.split("_dump")[0].replace("smart_naga_","") for f in c["files"])),
        c["xicc"] or "-", ",".join(sorted(sdpc)) or "-", max(c["times"])-min(c["times"]), len(c["msgs"])))
