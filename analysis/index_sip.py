# -*- coding: utf-8 -*-
import os, sys, struct, json, re, glob

PCAP_DIR = r"W:\BACKUPS_others\naga_pcap"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sip_index.json")

MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
SIP_RE = re.compile(rb"^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|PRACK|UPDATE|INFO|NOTIFY|REFER|MESSAGE|SUBSCRIBE|PUBLISH|NOTIFY|SIP/2\.0)")

def parse_headers(text):
    try:
        head, _, body = text.partition(b"\r\n\r\n")
    except Exception:
        return None, b""
    lines = head.split(b"\r\n")
    if not lines:
        return None, b""
    first = lines[0].decode("utf-8", "replace")
    hdrs = {}
    cur = None
    for ln in lines[1:]:
        if ln[:1] in (b" ", b"\t") and cur:
            hdrs[cur] += b" " + ln.strip()
            continue
        if b":" in ln:
            k, _, v = ln.partition(b":")
            cur = k.strip().lower().decode("utf-8", "replace")
            hdrs[cur] = v.strip()
    h = {k: v.decode("utf-8", "replace") for k, v in hdrs.items()}
    h["_first"] = first
    h["_raw"] = head
    return h, body

def pcap_iter(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise SystemExit("PCAPNG not supported: " + path)
        end = MAGICS.get(magic)
        if end is None:
            raise SystemExit("unknown magic %r in %s" % (magic, path))
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        hdrlen = {1: 14, 113: 16, 276: 20, 0: 4}.get(linktype, 14)
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts_sec, ts_frac, incl, orig = struct.unpack(end + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            ts = ts_sec + ts_frac / (1e9 if end == ">" and magic in (b"\xa1\xb2\x3c\x4d",) or magic == b"\x4d\x3c\xb2\xa1" else 1e6)
            # normalize ns -> s
            if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                ts = ts_sec + ts_frac / 1e9
            yield ts, linktype, hdrlen, data

def get_udp(data, linktype, hdrlen):
    if linktype == 1:
        if len(data) < 14:
            return None
        eth = struct.unpack("!H", data[12:14])[0]
        off = 14
        while eth in (0x8100, 0x88a8, 0x9100) and len(data) >= off + 4:
            eth = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if eth != 0x0800:
            return None
    else:
        if linktype == 113 and len(data) >= 16:
            proto = struct.unpack("!H", data[14:16])[0]
            off = 16
            if proto != 0x0800:
                return None
        elif linktype == 276 and len(data) >= 20:
            proto = struct.unpack("!H", data[0:2])[0]
            off = 20
            if proto != 0x0800:
                return None
        else:
            off = hdrlen
    if len(data) < off + 20:
        return None
    if data[off] >> 4 != 4:
        return None
    ihl = (data[off] & 0xF) * 4
    proto = data[off + 9]
    if proto != 17:
        return None
    frag = struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF
    if frag:
        return None
    src = ".".join(str(b) for b in data[off + 12:off + 16])
    dst = ".".join(str(b) for b in data[off + 16:off + 20])
    u = off + ihl
    if len(data) < u + 8:
        return None
    sport, dport, ulen, _ = struct.unpack("!HHHH", data[u:u + 8])
    payload = data[u + 8:u + ulen] if ulen >= 8 else data[u + 8:]
    return src, dst, sport, dport, payload

def get_tcp_payload(data, linktype, hdrlen):
    # minimal: return None (SIP over TCP ignored)
    return None

records = []
files = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
for path in files:
    name = os.path.basename(path)
    n = 0
    try:
        for ts, linktype, hdrlen, data in pcap_iter(path):
            r = get_udp(data, linktype, hdrlen)
            if r is None:
                continue
            src, dst, sport, dport, payload = r
            if sport not in (5060, 5061, 5070) and dport not in (5060, 5061, 5070):
                continue
            if not payload or not SIP_RE.match(payload):
                continue
            h, body = parse_headers(payload)
            if h is None:
                continue
            first = h["_first"]
            method, status = "", ""
            if first.startswith("SIP/2.0"):
                parts = first.split()
                status = parts[1] if len(parts) > 1 else ""
            else:
                method = first.split(" ")[0]
            rec = dict(file=name, ts=round(ts, 6), src=src, dst=dst, sport=sport, dport=dport,
                       method=method, status=status,
                       call_id=h.get("call-id", ""),
                       cseq=h.get("cseq", ""),
                       frm=h.get("from", ""), to=h.get("to", ""),
                       xicc=h.get("x-icc_uuid", ""),
                       xcall=h.get("x-call_uuid", ""),
                       ctype=h.get("content-type", ""),
                       rawlen=len(payload))
            # SDP summary
            if b"application/sdp" in h.get("_raw", b"").lower() and body:
                txt = body.decode("utf-8", "replace")
                rec["sdp_m"] = re.findall(r"^m=.*$", txt, re.M)
                rec["sdp_c"] = re.findall(r"^c=IN IP4 (\S+)", txt, re.M)
                rec["sdp_o"] = re.findall(r"^o=\S+ \S+ \S+ IN IP4 (\S+)", txt, re.M)
            rec["has181"] = b"154.48.201.181" in payload
            rec["has178"] = b"154.48.201.178" in payload
            records.append(rec)
            n += 1
    except SystemExit as e:
        print("SKIP:", e)
        continue
    print("%-40s sip_messages=%d" % (name, n))

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(records, f)
print("total SIP messages:", len(records), "->", OUT)
