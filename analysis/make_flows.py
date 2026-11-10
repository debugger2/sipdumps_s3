#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sngrep-style text SIP flow for each merged pcap.

Left pane  : timestamps, message labels, arrows between participant columns.
Right pane : raw SIP text of every message (like sngrep payload view).
"""
import struct
import re
import datetime
import subprocess
from pathlib import Path

MERGED_DIR = Path(r"W:/BACKUPS_others/naga_pcap/merged_calls")
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

GUT = 20  # left gutter width for timestamps/deltas

FS_NAMES = {
    "141.94.5.146": "fs09",
    "141.94.5.148": "fs10",
    "141.94.5.145": "fs12",
    "51.195.69.234": "fs11",
    "51.195.69.226": "fs13",
}

REQ_RE = re.compile(
    r"^(INVITE|ACK|BYE|CANCEL|REGISTER|PRACK|OPTIONS|INFO|UPDATE|REFER|"
    r"NOTIFY|SUBSCRIBE|MESSAGE|PUBLISH)\s"
)
RESP_RE = re.compile(r"^SIP/2\.0\s+(\d{3})\s*(.*)$")


def role(ip):
    if ip == "51.38.198.83":
        return "KAMAILIO proxy"
    if ip == "51.38.198.93":
        return "UPSTREAM a-leg gw"
    if ip == "154.48.201.181":
        return "PROVIDER sip"
    if ip == "154.48.201.178":
        return "PROVIDER media"
    if ip in FS_NAMES:
        return "FREESWITCH %s" % FS_NAMES[ip]
    if re.match(r"^141\.94\.5\.\d+$", ip):
        return "FREESWITCH"
    return "unknown"


def role_rank(ip):
    r = role(ip)
    if r.startswith("FREESWITCH"):
        return 0
    if r.startswith("KAMAILIO"):
        return 1
    if r.startswith("PROVIDER"):
        return 2
    return 3


def read_frames(path):
    data = Path(path).read_bytes()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise RuntimeError("unknown pcap magic %r in %s" % (magic, path))
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 276:
        raise RuntimeError("unsupported linktype %d in %s" % (linktype, path))
    frames = []
    pos = 24
    n = len(data)
    while pos + 16 <= n:
        _sec, sub, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        buf = data[pos:pos + incl]
        pos += incl
        ts = _sec + sub / (1e9 if nano else 1e6)
        frames.append((ts, buf))
    return frames


def parse_udp(buf):
    """Return (src, dst, sport, dport, payload, is_frag, mf, frag_off, ident, ip_payload_len, ihl)."""
    if len(buf) < 40:
        return None
    if struct.unpack(">H", buf[0:2])[0] != 0x0800:
        return None
    ip = buf[20:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0xF) * 4
    if ip[9] != 17:
        return None
    total_len = struct.unpack(">H", ip[2:4])[0]
    ident = struct.unpack(">H", ip[4:6])[0]
    ff = struct.unpack(">H", ip[6:8])[0]
    mf = bool(ff & 0x2000)
    foff = (ff & 0x1FFF) * 8
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    plen = total_len - ihl
    if plen <= 0 or ihl + plen > len(ip):
        plen = len(ip) - ihl
    piece = ip[ihl:ihl + plen]
    return src, dst, ident, mf, foff, piece


def is_sip(text):
    line = text.split("\r\n", 1)[0].split("\n", 1)[0]
    return bool(REQ_RE.match(line) or RESP_RE.match(line))


def msg_label(text):
    line = text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    m = REQ_RE.match(line)
    if m:
        label = m.group(1)
    else:
        m = RESP_RE.match(line)
        if not m:
            return "?"
        label = (m.group(1) + " " + m.group(2).strip()).strip()
    head, _, _body = _split_sip(text)
    if re.search(r"^content-type\s*:\s*application/sdp", head, re.I | re.M):
        label += " (SDP)"
    return label


def _split_sip(text):
    idx = text.find("\r\n\r\n")
    sep = 4
    if idx < 0:
        idx = text.find("\n\n")
        sep = 2
    if idx < 0:
        return text, "", ""
    return text[:idx], text[idx:idx + sep], text[idx + sep:]


def extract_sip_messages(path):
    frames = read_frames(path)
    msgs = []
    frags = {}
    for fidx, (ts, buf) in enumerate(frames):
        p = parse_udp(buf)
        if p is None:
            continue
        src, dst, ident, mf, foff, piece = p
        if not mf and foff == 0:
            if len(piece) < 8:
                continue
            sport, dport, ulen = struct.unpack(">HHH", piece[:6])
            payload = piece[8:ulen] if ulen >= 8 else piece[8:]
            text = payload.decode("utf-8", errors="replace")
            if is_sip(text):
                msgs.append({"ts": ts, "frame": fidx + 1, "src": src, "sport": sport,
                             "dst": dst, "dport": dport, "text": text, "trunc": False})
            continue
        key = (src, dst, ident)
        e = frags.get(key)
        if e is None:
            e = frags[key] = {"parts": {}, "mf": False, "ts": ts, "frame": fidx + 1,
                              "src": src, "dst": dst}
        e["parts"][foff] = piece
        e["mf"] = e["mf"] or mf
        if foff == 0 and len(piece) >= 8:
            sport, dport, ulen = struct.unpack(">HHH", piece[:6])
            e["sport"], e["dport"], e["ulen"] = sport, dport, ulen
        if not mf:
            e["last_end"] = foff + len(piece)
    for e in frags.values():
        if "sport" not in e:
            continue
        buf = bytearray()
        cur = 0
        complete = True
        for off in sorted(e["parts"]):
            if off > cur:
                complete = False
                break
            buf += e["parts"][off]
            cur = off + len(e["parts"][off])
        ulen = e.get("ulen", 0)
        trunc = (not complete) or e["mf"] or (ulen and cur < ulen)
        payload = bytes(buf[8:ulen] if ulen >= 8 else buf[8:])
        text = payload.decode("utf-8", errors="replace")
        if is_sip(text):
            msgs.append({"ts": e["ts"], "frame": e["frame"], "src": e["src"],
                         "sport": e["sport"], "dst": e["dst"], "dport": e["dport"],
                         "text": text, "trunc": trunc})
    msgs.sort(key=lambda m: (m["ts"], m["frame"]))
    return msgs


def call_id_of(text):
    m = re.search(r"^Call-ID:\s*(.+)$", text, re.I | re.M)
    return m.group(1).strip() if m else ""


def rtp_streams(pcap):
    proc = subprocess.Popen([TSHARK, "-r", str(pcap), "-n", "-q", "-z", "rtp,streams"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate(timeout=600)
    return out.decode("utf-8", errors="replace")


def tstr(ts):
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S") + ".%06d" % dt.microsecond


def build_flow(pcap):
    msgs = extract_sip_messages(pcap)
    if not msgs:
        return None

    # columns: distinct SIP endpoints, fs/proxy/provider order, then first seen
    first_seen = {}
    for m in msgs:
        for ep in ((m["src"], m["sport"]), (m["dst"], m["dport"])):
            if ep not in first_seen:
                first_seen[ep] = len(first_seen)
    cols = sorted(first_seen, key=lambda ep: (role_rank(ep[0]), first_seen[ep]))
    idx = {ep: i for i, ep in enumerate(cols)}
    ncol = len(cols)

    labels = ["%s:%d" % ep for ep in cols]
    roles = [role(ep[0]) for ep in cols]
    msg_labels = [msg_label(m["text"]) for m in msgs]
    CW = max([26] + [len(s) + 4 for s in labels] + [len(s) + 4 for s in msg_labels])
    CW = min(CW, 44)

    def blank_line():
        return " " * GUT

    def col_pos(k):
        return k * (CW + 1)

    def put_bars(buf):
        for k in range(ncol + 1):
            if 0 <= col_pos(k) < len(buf):
                buf[col_pos(k)] = "│"
        return buf

    def make_row(content_map):
        buf = [" "] * (ncol * (CW + 1) + 1)
        for pos, ch in content_map:
            if 0 <= pos < len(buf):
                buf[pos] = ch
        put_bars(buf)
        return "".join(buf)

    def center_in(col, s):
        start = col_pos(col) + 1
        width = CW
        p = start + max(0, (width - len(s)) // 2)
        return [(p + i, c) for i, c in enumerate(s)]

    def label_row(i, j):
        lo, hi = min(i, j), max(i, j)
        start = col_pos(lo) + 1
        end = col_pos(hi) + CW
        allowed = list(range(start, end + 1))
        s = msg_labels_current[:len(allowed)]
        off = max(0, (len(allowed) - len(s)) // 2)
        buf = list(make_row([]))
        for pos, c in zip(allowed[off:off + len(s)], s):
            buf[pos] = c
        return "".join(buf)

    def arrow_row(i, j):
        lo, hi = min(i, j), max(i, j)
        start = col_pos(lo) + 1
        end = col_pos(hi) + CW
        cmap = []
        if abs(i - j) > 1:
            for pos in range(start, end + 1):
                if any(pos == col_pos(k) for k in range(ncol + 1)):
                    continue
                cmap.append((pos, "─"))
        if i < j:
            cmap.append((end, ">"))
            for pos in range(start, end):
                if not any(pos == col_pos(k) for k in range(ncol + 1)):
                    cmap.append((pos, "─"))
        else:
            cmap.append((start, "<"))
            for pos in range(start + 1, end + 1):
                if not any(pos == col_pos(k) for k in range(ncol + 1)):
                    cmap.append((pos, "─"))
        return make_row(cmap)

    rows = []
    # header rows
    hdr = " " * GUT
    rows.append(hdr + "".join(make_row(
        [(col_pos(k) + 1 + max(0, (CW - len(s)) // 2) + n, c)
         for k, s in enumerate(labels) for n, c in enumerate(s)])))
    rows.append(hdr + "".join(make_row(
        [(col_pos(k) + 1 + max(0, (CW - len(s)) // 2) + n, c)
         for k, s in enumerate(roles) for n, c in enumerate(s)])))
    sep = []
    for pos in range(ncol * (CW + 1) + 1):
        sep.append("┬" if any(pos == col_pos(k) for k in range(ncol + 1)) else "─")
    rows.append(hdr + "".join(sep))

    # message rows
    for n, m in enumerate(msgs):
        msg_labels_current = msg_labels[n]
        i = idx[(m["src"], m["sport"])]
        j = idx[(m["dst"], m["dport"])]
        g = "  " + tstr(m["ts"]) + "   "
        assert len(g) == GUT, len(g)
        rows.append(g + label_row(i, j))
        if n + 1 < len(msgs):
            delta = msgs[n + 1]["ts"] - m["ts"]
            g2 = "  " + ("+%.6f" % delta).rjust(15) + "   "
        else:
            g2 = " " * GUT
        rows.append(g2 + arrow_row(i, j))

    # right pane: raw text of every message
    pane = []
    for n, m in enumerate(msgs):
        cid = call_id_of(m["text"])
        cid_s = (cid[:20] + "..") if len(cid) > 22 else cid
        head = ("──── frame %d | %s | %s | %s:%d -> %s:%d | call-id %s"
                % (m["frame"], tstr(m["ts"]), msg_labels[n],
                   m["src"], m["sport"], m["dst"], m["dport"], cid_s))
        if m["trunc"]:
            head += " | TRUNCATED"
        head += " " + "─" * 8
        pane.append(head)
        pane.extend(m["text"].splitlines())
        if m["trunc"]:
            pane.append("[ WARNING: SIP message incomplete in capture (missing IP fragment) ]")

    flow_w = GUT + ncol * (CW + 1) + 1
    payoff = flow_w + 1
    lines = []
    for n in range(max(len(rows), len(pane))):
        left = rows[n] if n < len(rows) else " " * flow_w
        if n < len(pane):
            left = left.ljust(payoff) + pane[n]
        lines.append(left.rstrip())
    return msgs, cols, roles, lines


def main():
    for pcap in sorted(MERGED_DIR.glob("*.pcap")):
        print("Processing %s ..." % pcap.name, flush=True)
        out = pcap.with_name(pcap.stem + "_flow.txt")
        result = build_flow(pcap)
        if result is None:
            print("  no SIP messages, skipped")
            continue
        msgs, cols, roles, lines = result
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write("=" * 100 + "\n")
            f.write("CALL SIP FLOW (sngrep-style): %s\n" % pcap.stem)
            f.write("Source: %s\n" % pcap.name)
            f.write("=" * 100 + "\n\n")
            f.write("PARTICIPANTS (columns left -> right):\n")
            for ep, r in zip(cols, roles):
                f.write("  %-22s %s\n" % ("%s:%d" % ep, r))
            f.write("\n")
            f.write("\n".join(lines))
            f.write("\n\n")
            f.write("RTP STREAMS (tshark -z rtp,streams)\n")
            f.write("-" * 100 + "\n")
            f.write(rtp_streams(pcap))
            f.write("\n")
        print("  -> %s (%d bytes, %d SIP msgs)" % (out.name, out.stat().st_size, len(msgs)),
              flush=True)


if __name__ == "__main__":
    main()
