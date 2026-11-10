# -*- coding: utf-8 -*-
import os, json, struct, re, collections

PCAP_DIR = r"W:\BACKUPS_others\naga_pcap"
OUT_DIR = os.path.join(PCAP_DIR, "merged_calls")
recs = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sip_index.json"), encoding="utf-8"))
MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}

def pcap_iter(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        end = MAGICS[gh[:4]]
        ns = gh[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            a, b, incl, orig = struct.unpack(end + "IIII", ph)
            data = f.read(incl)
            yield a + b / (1e9 if ns else 1e6), data

def udp(data):
    lt_ok = len(data) >= 20
    if not lt_ok:
        return None
    if struct.unpack("!H", data[0:2])[0] == 0x0800:
        off = 20  # SLL2
    elif len(data) > 16 and struct.unpack("!H", data[14:16])[0] == 0x0800:
        off = 16
    else:
        return None
    if data[off] >> 4 != 4:
        return None
    ihl = (data[off] & 0xF) * 4
    if data[off + 9] != 17:
        return None
    src = ".".join(map(str, data[off + 12:off + 16]))
    dst = ".".join(map(str, data[off + 16:off + 20]))
    u = off + ihl
    sport, dport, ulen, _ = struct.unpack("!HHHH", data[u:u + 8])
    return src, dst, sport, dport

# specs (та же логика, что и в build_calls)
dialogs = collections.OrderedDict()
for r in recs:
    cid = r["call_id"]
    if not cid:
        continue
    d = dialogs.setdefault(cid, dict(call_id=cid, files=set(), msgs=[], has181=False, has178=False, xicc="", answered=False, times=[]))
    d["files"].add(r["file"]); d["msgs"].append(r); d["times"].append(r["ts"])
    if r.get("has181"): d["has181"] = True
    if r.get("has178"): d["has178"] = True
    if r["method"] == "INVITE" and r["xicc"] and not d["xicc"]: d["xicc"] = r["xicc"]
    if r["status"] == "200" and r["cseq"].upper().endswith("INVITE"): d["answered"] = True
by_xicc = collections.defaultdict(list)
for d in dialogs.values():
    if d["xicc"]:
        by_xicc[d["xicc"]].append(d)
cands = [d for d in dialogs.values() if (d["has181"] or d["has178"]) and d["answered"]]

specs = []
for d in cands:
    lp = rp = None
    for m in d["msgs"]:
        if not m.get("sdp_m"):
            continue
        mm = re.match(r"m=audio (\d+)", m["sdp_m"][0])
        if not mm:
            continue
        if m.get("sdp_c") and "154.48.201.178" in " ".join(m["sdp_c"]):
            rp = rp or int(mm.group(1))
        elif lp is None:
            lp = int(mm.group(1))
    xicc = d["xicc"]
    legs = by_xicc.get(xicc, [d]) if xicc else [d]
    fs = sorted(set(f for x in legs for f in x["files"] if "_fs" in f))
    t0 = min(min(x["times"]) for x in legs) - 3
    t1 = max(max(x["times"]) for x in legs) + 8
    specs.append(dict(xicc=xicc or d["call_id"], fs=fs, lport=lp, rport=rp, t0=t0, t1=t1))

print("%-38s %8s %8s %8s %8s %s" % ("call", "src_media", "out_media", "src_sip", "out_sip", "status"))
for s in specs:
    ports = {s["lport"], s["lport"] + 1, s["rport"], s["rport"] + 1}
    src_media = src_sip = 0
    for f in s["fs"]:
        for ts, data in pcap_iter(os.path.join(PCAP_DIR, f)):
            if not (s["t0"] <= ts <= s["t1"]):
                continue
            r = udp(data)
            if not r:
                continue
            a, b, sp, dp = r
            if sp not in ports or dp not in ports:
                continue
            if a != "154.48.201.178" and b != "154.48.201.178":
                continue
            if 5060 in (sp, dp) or 5061 in (sp, dp):
                src_sip += 1
            else:
                src_media += 1
    safe = re.sub(r'[<>:"/\|?*]', "_", s["xicc"])
    p = os.path.join(OUT_DIR, safe + ".pcap")
    out_media = out_sip = 0
    if os.path.exists(p):
        for ts, data in pcap_iter(p):
            r = udp(data)
            if not r:
                continue
            a, b, sp, dp = r
            if 5060 in (sp, dp) or 5061 in (sp, dp):
                out_sip += 1
            else:
                out_media += 1
    ok = (src_media == out_media) and out_sip > 0
    print("%-38s %8d %8d %8d %8d %s" % (s["xicc"][:38], src_media, out_media, src_sip, out_sip, "OK" if ok else "MISMATCH"))
