# -*- coding: utf-8 -*-
import subprocess, os, sys, wave, audioop, math, collections

TSH = r"C:\Program Files\Wireshark\tshark.exe"
PCAP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "smarted_naga_calls_161026_fs14.pcap")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audio")
os.makedirs(OUT, exist_ok=True)

RTP_PORTS = [23636,29026,24686,23610,22810,24014,22412,22732,27468,20052,21164,
             28024,23102,24606,14042,15748,47900,45728,11658,26194,14514,42374,
             15418,44052,47920,34190,30068,11858]
cmd = [TSH, "-r", PCAP]
for p in RTP_PORTS:
    cmd += ["-d", "udp.port==%d,rtp" % p]
cmd += ["-Y", "rtp && rtp.payload", "-T", "fields",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "rtp.ssrc", "-e", "rtp.seq", "-e", "rtp.timestamp", "-e", "rtp.p_type", "-e", "rtp.payload"]

print("extracting...")
out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode("utf-8", "replace")

streams = collections.OrderedDict()
for line in out.splitlines():
    f = line.split("\t")
    if len(f) < 9 or not f[8]:
        continue
    t, src, sp, dp, ssrc, seq, ts, pt = f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]
    if pt not in ("0", "8"):
        continue
    try:
        t = float(t); seq = int(seq); ts = int(ts)
        payload = bytes.fromhex(f[8].replace(":", ""))
    except ValueError:
        continue
    key = (src, int(sp), f[3] and int(dp), ssrc)
    streams.setdefault(key, []).append((t, seq, ts, int(pt), payload))
print("streams: %d, packets: %d" % (len(streams), sum(len(v) for v in streams.values())))

def mos_from_loss(ppl):
    if ppl < 0: ppl = 0
    ie_eff = 95.0 * (ppl / (ppl + 4.3))
    R = 93.2 - ie_eff
    if R > 100: R = 100.0
    if R < 0: R = 0.0
    mos = 1.0 + 0.035*R + R*(R-60.0)*(100.0-R)*7e-6
    return R, mos

rows = []
for key, pkts in streams.items():
    src, sp, dp, ssrc = key
    # unwrap seq in capture order
    exts = []
    prev = None
    base = 0
    for (t, seq, ts, pt, pl) in pkts:
        if prev is None:
            e = seq
        else:
            cand = [seq + (base >> 16 << 16) + d * 65536 for d in (-1, 0, 1)]
            e = min(cand, key=lambda c: abs(c - prev))
        exts.append(e)
        prev = e
        base = e
    uniq = sorted(set(exts))
    lo, hi = uniq[0], uniq[-1]
    expected = hi - lo + 1
    lost = expected - len(uniq)
    dup = len(exts) - len(uniq)
    ooo = sum(1 for i in range(1, len(exts)) if exts[i] <= exts[i-1])
    durs = [pkts[i+1][0]-pkts[i][0] for i in range(len(pkts)-1)]
    durs = [d for d in durs if d >= 0]
    mean_delta = sum(durs)/len(durs) if durs else 0
    max_delta = max(durs) if durs else 0
    gaps = sum(1 for d in durs if d > 0.04)
    # RFC3550 jitter
    J = 0.0
    prev_arr = prev_ts = None
    for (t, seq, ts, pt, pl) in pkts:
        if prev_arr is not None:
            D = (t - prev_arr) - (ts - prev_ts) / 8000.0
            J += (abs(D) - J) / 16.0
        prev_arr, prev_ts = t, ts
    dur = pkts[-1][0] - pkts[0][0]
    ppl = lost / float(expected) if expected else 0.0
    R, mos = mos_from_loss(ppl)
    rows.append(dict(src=src, sp=sp, dp=dp, ssrc=ssrc, pt=pkts[0][3], n=len(pkts),
                     lost=lost, dup=dup, ooo=ooo, expected=expected, start=pkts[0][0],
                     end=pkts[-1][0], dur=dur, mean_delta=mean_delta, max_delta=max_delta,
                     gaps=gaps, jitter=J*1000.0, R=R, mos=mos, pkts=pkts))

rows.sort(key=lambda r: r["start"])
fmt = "%-16s %-5s %-16s %-5s %-9s %-10s %5s %5s %5s %6s %7s %7s %5s %6s"
print(fmt % ("SRC","PORT","DST","PORT","SSRC","codec","pkts","lost","ooo","dur_s","meanD_ms","maxD_ms","jit","MOS"))
for r in rows:
    print(fmt % (r["src"], r["sp"], "154.48.201.178" if r["sp"] in RTP_PORTS and int(r["src"].split(".")[-1])==87 else r["dp"],
                 r["dp"], r["ssrc"], "PCMU" if r["pt"]==0 else "PCMA", r["n"], r["lost"], r["ooo"],
                 "%.1f" % r["dur"], "%.2f" % (r["mean_delta"]*1000), "%.1f" % (r["max_delta"]*1000),
                 "%.2f" % r["jitter"], "%.2f" % r["mos"]))

# audio extraction
import datetime
for r in rows:
    exts = []
    prev = base = 0
    items = []
    for (t, seq, ts, pt, pl) in r["pkts"]:
        if not items:
            e = seq
        else:
            cand = [seq + (base >> 16 << 16) + d * 65536 for d in (-1, 0, 1)]
            e = min(cand, key=lambda c: abs(c - prev))
        items.append((e, t, pl))
        prev, base = e, e
    items.sort(key=lambda x: x[0])
    # drop duplicate seq (keep first)
    clean, seen = [], set()
    for e, t, pl in items:
        if e in seen: continue
        seen.add(e); clean.append(pl)
    raw = b"".join(clean)
    lin = audioop.ulaw2lin(raw, 2) if r["pt"] == 0 else audioop.alaw2lin(raw, 2)
    # speech activity
    frame = 320  # 20ms * 2ch bytes
    lv = [audioop.rms(lin[i:i+frame], 2) for i in range(0, len(lin)-frame, frame)]
    active = sum(1 for v in lv if v > 300)
    pct = 100.0*active/len(lv) if lv else 0
    peak = audioop.max(lin, 2)
    clip = sum(1 for i in range(0, len(lin), 2) if abs(int.from_bytes(lin[i:i+2], "little", signed=True)) >= 32700)
    r["speech"] = pct; r["peak"] = peak; r["clip"] = clip
    ts = datetime.datetime.utcfromtimestamp(r["start"]).strftime("%H%M%S")
    name = "%s_%s_%d_%s_%d.wav" % (ts, r["sp"], r["dp"], r["ssrc"].replace("0x",""), r["pt"])
    path = os.path.join(OUT, name)
    w = wave.open(path, "wb")
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
    w.writeframes(lin); w.close()
    r["wav"] = name

print()
print("WAVs written to", OUT)
for r in rows:
    print("%s  %-15s:%-5s -> %-15s:%-5s  %-5s dur=%6.1fs lost=%3d mos=%.2f speech=%4.1f%% peak=%d wav=%s" % (
        datetime.datetime.utcfromtimestamp(r["start"]).strftime("%H:%M:%S"),
        r["src"], r["sp"], "154.48.201.178" if r["src"].endswith(".87") else r["dp"], r["dp"],
        "PCMU" if r["pt"]==0 else "PCMA", r["dur"], r["lost"], r["mos"], r["speech"], r["peak"], r["wav"]))
