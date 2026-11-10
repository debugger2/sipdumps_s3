# -*- coding: utf-8 -*-
import os, sys, json, struct, re, collections, audioop

HERE = os.path.dirname(os.path.abspath(__file__))
PCAP_DIR = r"W:\BACKUPS_others\naga_pcap"
OUT_DIR = os.path.join(PCAP_DIR, "merged_calls")
os.makedirs(OUT_DIR, exist_ok=True)
recs = json.load(open(os.path.join(HERE, "sip_index.json"), encoding="utf-8"))

MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


def pcap_iter(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        end = MAGICS[magic]
        ns = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts_sec, ts_frac, incl, orig = struct.unpack(end + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            ts = ts_sec + ts_frac / (1e9 if ns else 1e6)
            yield ts, linktype, data


def udp_payload(data, linktype):
    if linktype == 1:
        if len(data) < 14:
            return None
        eth = struct.unpack("!H", data[12:14])[0]
        off = 14
        while eth in (0x8100, 0x88A8, 0x9100):
            eth = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if eth != 0x0800:
            return None
    elif linktype == 113:
        if len(data) < 16 or struct.unpack("!H", data[14:16])[0] != 0x0800:
            return None
        off = 16
    elif linktype == 276:
        if len(data) < 20 or struct.unpack("!H", data[0:2])[0] != 0x0800:
            return None
        off = 20
    else:
        return None
    if len(data) < off + 20 or data[off] >> 4 != 4:
        return None
    ihl = (data[off] & 0xF) * 4
    if data[off + 9] != 17:
        return None
    if struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF:
        return None
    src = ".".join(map(str, data[off + 12:off + 16]))
    dst = ".".join(map(str, data[off + 16:off + 20]))
    u = off + ihl
    if len(data) < u + 8:
        return None
    sport, dport, ulen, _ = struct.unpack("!HHHH", data[u:u + 8])
    end = u + ulen if ulen >= 8 else len(data)
    payload = data[u + 8:end]
    return src, dst, sport, dport, payload


SIP_RE = re.compile(rb"^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|PRACK|UPDATE|INFO|NOTIFY|REFER|MESSAGE|SUBSCRIBE|PUBLISH|SIP/2\.0)")


def sip_call_id(payload):
    if not payload or not SIP_RE.match(payload):
        return None
    m = re.search(rb"^Call-ID:\s*(.+)$", payload, re.M | re.I)
    return m.group(1).strip().decode("utf-8", "replace") if m else None


def rtp_parse(p):
    if len(p) < 12 or p[0] >> 6 != 2:
        return None
    if p[1] in (200, 201, 202, 203, 204):  # RTCP SR/RR/SDES/BYE/APP
        return None
    cc = p[0] & 0x0F
    x = (p[0] >> 4) & 1
    pt = p[1] & 0x7F
    seq = struct.unpack("!H", p[2:4])[0]
    ssrc = struct.unpack("!I", p[8:12])[0]
    hlen = 12 + 4 * cc
    if x:
        if len(p) < hlen + 4:
            return None
        extlen = struct.unpack("!H", p[hlen + 2:hlen + 4])[0]
        hlen += 4 + 4 * extlen
    if len(p) <= hlen:
        return None
    return pt, seq, ssrc, p[hlen:]


# ---- диалоги из индекса ----
dialogs = collections.OrderedDict()
for r in recs:
    cid = r["call_id"]
    if not cid:
        continue
    d = dialogs.setdefault(cid, dict(call_id=cid, files=set(), msgs=[], has181=False, has178=False,
                                     xicc="", answered=False, times=[]))
    d["files"].add(r["file"])
    d["msgs"].append(r)
    d["times"].append(r["ts"])
    if r.get("has181"):
        d["has181"] = True
    if r.get("has178"):
        d["has178"] = True
    if r["method"] == "INVITE" and r["xicc"] and not d["xicc"]:
        d["xicc"] = r["xicc"]
    if r["status"] == "200" and r["cseq"].upper().endswith("INVITE"):
        d["answered"] = True

by_xicc = collections.defaultdict(list)
for d in dialogs.values():
    if d["xicc"]:
        by_xicc[d["xicc"]].append(d)

cands = [d for d in dialogs.values() if (d["has181"] or d["has178"]) and d["answered"]]
print("answered operator dialogs:", len(cands))

# ---- спецификация вызова ----
specs = []
for d in cands:
    local_port = remote_port = None
    for m in d["msgs"]:
        if not m.get("sdp_m"):
            continue
        mm = re.match(r"m=audio (\d+)", m["sdp_m"][0])
        if not mm:
            continue
        port = int(mm.group(1))
        is_remote = bool(m.get("sdp_c")) and "154.48.201.178" in " ".join(m["sdp_c"])
        if is_remote:
            if remote_port is None:
                remote_port = port
        elif local_port is None:
            local_port = port
    fs_files = sorted(set(f for f in d["files"] if "_fs" in f))
    klb_files = sorted(set(f for f in d["files"] if "_klb" in f))
    xicc = d["xicc"]
    legs = by_xicc.get(xicc, [d]) if xicc else [d]
    for leg in legs:
        fs_files.extend(f for f in leg["files"] if "_fs" in f)
        klb_files.extend(f for f in leg["files"] if "_klb" in f)
    fs_files = sorted(set(fs_files))
    klb_files = sorted(set(klb_files))
    all_cids = sorted(set(x["call_id"] for x in legs))
    t0 = min(min(x["times"]) for x in legs)
    t1 = max(max(x["times"]) for x in legs)
    specs.append(dict(cid=d["call_id"], xicc=xicc, fs=fs_files, klb=klb_files, cids=all_cids,
                      lport=local_port, rport=remote_port, t0=t0, t1=t1))

for s in specs:
    print("%s cid=%s fs=%s lport=%s rport=%s window=%.0fs legs=%d" % (
        s["xicc"] or "(no-icc)", s["cid"][:20],
        ",".join(x.replace("smart_naga_", "").replace("_dump2110.pcap", "") for x in s["fs"]),
        s["lport"], s["rport"], s["t1"] - s["t0"], len(s["cids"])))

# ---- сбор пакетов ----
SIP_PORTS = (5060, 5061, 5070)


def src_linktype(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        return struct.unpack(MAGICS[gh[:4]] + "I", gh[20:24])[0]


def write_pcap_header(f, linktype):
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))


def write_pkt(f, ts, data):
    sec = int(ts)
    usec = int(round((ts - sec) * 1e6))
    f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
    f.write(data)


stats = {}
bufs = collections.defaultdict(list)
linktypes = {}
try:
    for s in specs:
        key = s["xicc"] or s["cid"]
        if key in stats:
            continue
        stats[key] = dict(fwd_pkts=0, rev_pkts=0, fwd_bytes=0, rev_bytes=0, fwd_active=0, fwd_frames=0,
                          rev_active=0, rev_frames=0, pt=set(), loss={}, ssrcs=set(),
                          sip_fs=0, sip_klb=0, rtp_first=None, rtp_last=None)

    byfile = collections.defaultdict(list)
    for s in specs:
        for f in s["fs"]:
            byfile[f].append(s)

    for fname, slist in sorted(byfile.items()):
        path = os.path.join(PCAP_DIR, fname)
        cids = set()
        for s in slist:
            cids.update(s["cids"])
        print("scanning", fname, "...")
        lt = src_linktype(path)
        for ts, linktype, data in pcap_iter(path):
            r = udp_payload(data, linktype)
            if r is None:
                continue
            src, dst, sport, dport, payload = r
            if sport in SIP_PORTS or dport in SIP_PORTS:
                cid = sip_call_id(payload)
                if cid and cid in cids:
                    for s in slist:
                        if cid in s["cids"]:
                            key = s["xicc"] or s["cid"]
                            bufs[key].append((ts, data))
                            linktypes.setdefault(key, lt)
                            stats[key]["sip_fs"] += 1
                            break
                    continue
            if dst != "154.48.201.178" and src != "154.48.201.178":
                continue
            for s in slist:
                key = s["xicc"] or s["cid"]
                if not (s["lport"] and s["rport"]):
                    continue
                ports = {s["lport"], s["lport"] + 1, s["rport"], s["rport"] + 1}
                if sport not in ports or dport not in ports:
                    continue
                if not (s["t0"] - 3 <= ts <= s["t1"] + 8):
                    continue
                bufs[key].append((ts, data))
                linktypes.setdefault(key, lt)
                st = stats[key]
                direction = "fwd" if dst == "154.48.201.178" else "rev"
                if direction == "fwd":
                    st["fwd_pkts"] += 1
                    st["fwd_bytes"] += len(payload)
                else:
                    st["rev_pkts"] += 1
                    st["rev_bytes"] += len(payload)
                if st["rtp_first"] is None or ts < st["rtp_first"]:
                    st["rtp_first"] = ts
                if st["rtp_last"] is None or ts > st["rtp_last"]:
                    st["rtp_last"] = ts
                pr = rtp_parse(payload)
                if pr:
                    pt, seq, ssrc, body = pr
                    st["pt"].add(pt)
                    st["ssrcs"].add(ssrc)
                    L = st["loss"].setdefault((src, sport, ssrc), dict(prev=None, ext=0, lo=None, hi=None, seen=set(), dup=0))
                    if L["prev"] is None:
                        L["ext"] = seq
                    else:
                        delta = (seq - L["prev"]) & 0xFFFF
                        if delta >= 32768:
                            delta -= 65536
                        L["ext"] += delta
                    L["prev"] = seq
                    e = L["ext"]
                    if e in L["seen"]:
                        L["dup"] += 1
                    L["seen"].add(e)
                    L["lo"] = e if L["lo"] is None else min(L["lo"], e)
                    L["hi"] = e if L["hi"] is None else max(L["hi"], e)
                    if pt in (0, 8) and body:
                        lin = audioop.ulaw2lin(body, 2) if pt == 0 else audioop.alaw2lin(body, 2)
                        fr = 320
                        for i in range(len(lin) // fr):
                            v = audioop.rms(lin[i * fr:(i + 1) * fr], 2)
                            if direction == "fwd":
                                st["fwd_frames"] += 1
                                if v > 300:
                                    st["fwd_active"] += 1
                            else:
                                st["rev_frames"] += 1
                                if v > 300:
                                    st["rev_active"] += 1
                break

    kbyfile = collections.defaultdict(list)
    for s in specs:
        for f in s["klb"]:
            kbyfile[f].append(s)
    for fname, slist in sorted(kbyfile.items()):
        path = os.path.join(PCAP_DIR, fname)
        cids = set()
        for s in slist:
            cids.update(s["cids"])
        print("scanning", fname, "(klb) ...")
        lt = src_linktype(path)
        for ts, linktype, data in pcap_iter(path):
            r = udp_payload(data, linktype)
            if r is None:
                continue
            src, dst, sport, dport, payload = r
            if sport not in SIP_PORTS and dport not in SIP_PORTS:
                continue
            cid = sip_call_id(payload)
            if not cid or cid not in cids:
                continue
            for s in slist:
                if cid in s["cids"]:
                    key = s["xicc"] or s["cid"]
                    if key in stats:
                        bufs[key].append((ts, data))
                        linktypes.setdefault(key, lt)
                        stats[key]["sip_klb"] += 1
                    break
finally:
    pass

# ---- отчёт ----
print("\n%-38s %6s %6s %6s %6s %8s %8s %6s" % ("icc_uuid", "sipFS", "sipKLB", "fwd", "rev", "speechF", "speechR", "voice"))
report = []
for s in specs:
    key = s["xicc"] or s["cid"]
    st = stats[key]
    pf = 100.0 * st["fwd_active"] / st["fwd_frames"] if st["fwd_frames"] else 0.0
    pr = 100.0 * st["rev_active"] / st["rev_frames"] if st["rev_frames"] else 0.0
    loss_tot = 0
    dup_tot = 0
    for (src, sport, ssrc), L in st["loss"].items():
        if L["lo"] is not None and L["hi"] is not None:
            loss_tot += (L["hi"] - L["lo"] + 1) - len(L["seen"])
        dup_tot += L["dup"]
    voice = (pf >= 5.0 or pr >= 5.0) and (st["fwd_pkts"] + st["rev_pkts"]) > 50
    report.append((key, st, pf, pr, loss_tot, dup_tot, voice))
    print("%-38s %6d %6d %6d %6d %7.1f%% %7.1f%% %6s" % (
        key, st["sip_fs"], st["sip_klb"], st["fwd_pkts"], st["rev_pkts"], pf, pr, "YES" if voice else "no"))

print()
for key, st, pf, pr, loss_tot, dup_tot, voice in report:
    safe = re.sub(r'[<>:"/\\|?*]', "_", key)
    path = os.path.join(OUT_DIR, safe + ".pcap")
    if not voice:
        if os.path.exists(path):
            os.remove(path)
        print("removed (no voice):", os.path.basename(path))
        continue
    pkts = sorted(bufs.get(key, ()), key=lambda x: x[0])
    if not pkts:
        if os.path.exists(path):
            os.remove(path)
        print("removed (no packets):", os.path.basename(path))
        continue
    with open(path, "wb") as op:
        write_pcap_header(op, linktypes.get(key, 276))
        for ts, data in pkts:
            write_pkt(op, ts, data)
    dur = (st["rtp_last"] - st["rtp_first"]) if st["rtp_first"] else 0
    print("KEPT %s  rtp_dur=%.1fs loss=%d dup=%d pt=%s ssrcs=%d size=%d KB" % (
        os.path.basename(path), dur, loss_tot, dup_tot, sorted(st["pt"]), len(st["ssrcs"]),
        os.path.getsize(path) // 1024))
