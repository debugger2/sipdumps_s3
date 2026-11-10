#!/usr/bin/env python3
"""Find call dumps in the S3 buckets for a time window, download + gunzip them,
merge the fragments from all hosts (SIP proxy klb + FreeSWITCH pbx) and write
one time-sorted pcap per call with its SIP and RTP.

Bucket layout (sipdumps_s3_upload):
    s3://<bucket>/<host-ip>/YYYY/MM/DD/YYYY-MM-DD_HH-MM-SS.pcap.gz
    (older keys: s3://<bucket>/<host-ip>/YYYY-MM-DD_HH-MM-SS.pcap.gz)
File names are the UTC start time of a tcpdump rotation (~3 min).

Examples:
    # list calls in a window (times are UTC unless an offset is given)
    s3_call_dump.py --from "2026-11-04 10:40" --to "2026-11-04 11:30" --list
    # one call by X-icc_uuid / Call-ID / number / IP
    s3_call_dump.py --from "2026-11-04 10:40" --to "2026-11-04 10:50" --icc-uuid de2dcbeb-...
    s3_call_dump.py --from "2026-11-04 10:40+02:00" --to "2026-11-04 10:50+02:00" --number 19363370359
    # everything in the window, merged into one pcap
    s3_call_dump.py --from "2026-11-04 10:40" --to "2026-11-04 10:45" --all

Needs boto3 and AWS credentials with read access to the buckets.
"""
import argparse
import collections
import datetime as dt
import gzip
import heapq
import os
import re
import shutil
import struct
import sys
import zlib
from concurrent.futures import ThreadPoolExecutor

BUCKETS = ["icc-klb-call-dumps", "icc-pbx-call-dumps"]
NAME_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})\.pcap(\.gz)?$")
EXTEND_STEP = 900          # seconds added per window extension when a call is not complete
MEDIA_PAD = (2.0, 10.0)    # RTP accepted this long before the first / after the last SIP message
DEDUP_WINDOW = 0.5         # same packet seen on two hosts within this time -> keep the first copy

SIP_START = re.compile(rb"^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|PRACK|UPDATE|INFO|NOTIFY|"
                       rb"REFER|MESSAGE|SUBSCRIBE|PUBLISH|SIP/2\.0) ")
MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
          b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}
LINKTYPE_RAW = 101


# ---------------------------------------------------------------- time
def parse_time(s):
    s = s.strip().replace("T", " ")
    m = re.match(r"^(.*?)(Z|[+-]\d{2}:?\d{2})?$", s)
    base, tz = m.group(1).strip(), m.group(2)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            t = dt.datetime.strptime(base, fmt)
            break
        except ValueError:
            continue
    else:
        raise SystemExit("bad time: %r" % s)
    off = 0
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        off = sign * (hh * 3600 + mm * 60)
    return t.replace(tzinfo=dt.timezone.utc).timestamp() - off


def fmt_ts(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- S3
class Store:
    def __init__(self, args):
        import boto3
        sess = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        self.s3 = sess.client("s3", region_name=args.region) if args.region else sess.client("s3")
        self.cache = args.cache
        self.buckets = args.bucket or BUCKETS
        self.host_filter = set(args.host or [])
        self._hosts = {}
        self._listed = {}

    def hosts(self, bucket):
        if bucket not in self._hosts:
            r = self.s3.list_objects_v2(Bucket=bucket, Delimiter="/")
            hs = [p["Prefix"].rstrip("/") for p in r.get("CommonPrefixes", [])]
            self._hosts[bucket] = [h for h in hs if not self.host_filter or h in self.host_filter]
        return self._hosts[bucket]

    def _list(self, bucket, prefix):
        if prefix not in self._listed:
            out = []
            pg = self.s3.get_paginator("list_objects_v2")
            for page in pg.paginate(Bucket=bucket, Prefix=prefix):
                out += [(o["Key"], o["Size"]) for o in page.get("Contents", [])]
            self._listed[prefix] = out
        return self._listed[prefix]

    def files(self, t_from, t_to):
        """Dump files (bucket, host, key, start_ts) whose capture overlaps [t_from, t_to]."""
        out = []
        for bucket in self.buckets:
            for host in self.hosts(bucket):
                cand = []
                day = dt.datetime.fromtimestamp(t_from, dt.timezone.utc).date() - dt.timedelta(days=1)
                last = dt.datetime.fromtimestamp(t_to, dt.timezone.utc).date()
                while day <= last:
                    for pre in ("%s/%s/" % (host, day.strftime("%Y/%m/%d")),
                                "%s/%s" % (host, day.strftime("%Y-%m-%d"))):
                        for key, size in self._list(bucket, pre):
                            m = NAME_RE.search(key)
                            if m and size > 64:
                                y, mo, d, hh, mi, ss = map(int, m.groups()[:6])
                                st = dt.datetime(y, mo, d, hh, mi, ss, tzinfo=dt.timezone.utc).timestamp()
                                cand.append((st, key))
                    day += dt.timedelta(days=1)
                cand.sort()
                for i, (st, key) in enumerate(cand):
                    nxt = cand[i + 1][0] if i + 1 < len(cand) else float("inf")
                    if st <= t_to and nxt >= t_from:
                        out.append((bucket, host, key, st))
        return out

    def fetch(self, items):
        """Download + gunzip into the cache; returns {key-tuple: local pcap path}."""
        def one(it):
            bucket, host, key, st = it
            dst = os.path.join(self.cache, bucket, key)
            if dst.endswith(".gz"):
                dst = dst[:-3]
            if not os.path.exists(dst):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                tmp = dst + ".part"
                body = self.s3.get_object(Bucket=bucket, Key=key)["Body"]
                with open(tmp, "wb") as f:
                    if key.endswith(".gz"):
                        with gzip.GzipFile(fileobj=body) as g:
                            shutil.copyfileobj(g, f)
                    else:
                        shutil.copyfileobj(body, f)
                os.replace(tmp, dst)
            return it, dst
        with ThreadPoolExecutor(8) as ex:
            return dict(ex.map(one, items))


# ---------------------------------------------------------------- pcap
def pcap_header(path):
    with open(path, "rb") as f:
        gh = f.read(24)
    if len(gh) < 24 or gh[:4] not in MAGICS:
        return None
    end, ns = MAGICS[gh[:4]]
    return end, ns, struct.unpack(end + "I", gh[20:24])[0]


def pcap_iter(path):
    hdr = pcap_header(path)
    if not hdr:
        return
    end, ns, lt = hdr
    div = 1e9 if ns else 1e6
    with open(path, "rb") as f:
        f.seek(24)
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            sec, frac, incl, _ = struct.unpack(end + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:      # truncated tail of a rotated file
                return
            yield sec + frac / div, lt, data


def ip_offset(lt, data):
    """Offset of the IPv4 header inside a frame, or None."""
    if lt == 1:
        off, eth = 14, struct.unpack("!H", data[12:14])[0] if len(data) >= 14 else 0
        while eth in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
            eth = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        return off if eth == 0x0800 else None
    if lt == 113:
        return 16 if len(data) >= 16 and data[14:16] == b"\x08\x00" else None
    if lt == 276:
        return 20 if len(data) >= 20 and data[0:2] == b"\x08\x00" else None
    if lt in (LINKTYPE_RAW, 228):
        return 0
    if lt == 0:   # BSD loopback
        return 4
    return None


class Pkt:
    __slots__ = ("ts", "lt", "data", "src", "dst", "proto", "ident", "frag_off", "mf",
                 "sport", "dport", "payload", "ipo")


def decode(ts, lt, data):
    o = ip_offset(lt, data)
    if o is None or len(data) < o + 20 or data[o] >> 4 != 4:
        return None
    p = Pkt()
    p.ts, p.lt, p.data, p.ipo = ts, lt, data, o
    ihl = (data[o] & 15) * 4
    tot = struct.unpack("!H", data[o + 2:o + 4])[0]
    p.ident = struct.unpack("!H", data[o + 4:o + 6])[0]
    fl = struct.unpack("!H", data[o + 6:o + 8])[0]
    p.mf, p.frag_off = bool(fl & 0x2000), (fl & 0x1FFF) * 8
    p.proto = data[o + 9]
    p.src = data[o + 12:o + 16]
    p.dst = data[o + 16:o + 20]
    end = min(len(data), o + tot) if tot else len(data)
    body = data[o + ihl:end]
    p.sport = p.dport = 0
    p.payload = body
    if p.frag_off == 0 and p.proto == 17 and len(body) >= 8:
        p.sport, p.dport = struct.unpack("!HH", body[:4])
        p.payload = body[8:]
    elif p.frag_off == 0 and p.proto == 6 and len(body) >= 20:
        p.sport, p.dport = struct.unpack("!HH", body[:4])
        p.payload = body[(body[12] >> 4) * 4:]
    return p


def ip_s(b):
    return "%d.%d.%d.%d" % tuple(b)


class Reassembler:
    """Joins IPv4 fragments of UDP datagrams so SIP bodies (SDP) are complete."""

    def __init__(self):
        self.parts = {}

    def add(self, p):
        key = (p.src, p.dst, p.ident, p.proto)
        st = self.parts.setdefault(key, {"chunks": {}, "total": None, "ts": p.ts})
        o = p.ipo
        ihl = (p.data[o] & 15) * 4
        tot = struct.unpack("!H", p.data[o + 2:o + 4])[0]
        st["chunks"][p.frag_off] = p.data[o + ihl:o + tot]
        if not p.mf:
            st["total"] = p.frag_off + len(st["chunks"][p.frag_off])
        if st["total"] is None:
            return None
        buf, pos = b"", 0
        for off in sorted(st["chunks"]):
            if off != pos:
                return None
            buf += st["chunks"][off]
            pos += len(st["chunks"][off])
        if pos != st["total"]:
            return None
        del self.parts[key]
        if p.proto != 17 or len(buf) < 8:
            return None
        return struct.unpack("!HH", buf[:4]) + (buf[8:],)


# ---------------------------------------------------------------- SIP index
def hdr(msg, *names):
    for n in names:
        m = re.search(rb"^" + n + rb"\s*:\s*(.*?)\r?$", msg, re.M | re.I)
        if m:
            return m.group(1).decode("utf-8", "replace").strip()
    return ""


def uri_user(v):
    m = re.search(r"sips?:([^@;>]+)@", v)
    return m.group(1) if m else ""


class Msg:
    __slots__ = ("ts", "host", "src", "dst", "sport", "dport", "call_id", "first", "method",
                 "status", "cseq", "from_u", "to_u", "ruri", "links", "media", "ua")


def parse_sip(ts, host, src, dst, sport, dport, payload):
    if not SIP_START.match(payload):
        return None
    head = payload.split(b"\r\n\r\n", 1)
    m = Msg()
    m.ts, m.host, m.src, m.dst, m.sport, m.dport = ts, host, src, dst, sport, dport
    m.call_id = hdr(head[0], b"Call-ID", b"i")
    if not m.call_id:
        return None
    m.first = head[0].split(b"\r\n", 1)[0].decode("utf-8", "replace")
    if m.first.startswith("SIP/2.0"):
        m.method, m.status = None, int(m.first.split()[1]) if len(m.first.split()) > 1 else 0
        m.ruri = ""
    else:
        m.method, m.status = m.first.split()[0], None
        m.ruri = m.first.split()[1] if len(m.first.split()) > 1 else ""
    m.cseq = hdr(head[0], b"CSeq").split()[-1:] or [""]
    m.cseq = m.cseq[0].upper()
    m.from_u = uri_user(hdr(head[0], b"From", b"f"))
    m.to_u = uri_user(hdr(head[0], b"To", b"t"))
    m.ua = hdr(head[0], b"User-Agent", b"Server")
    # every X-icc*uuid / X-*from_uuid value links B2BUA legs of the same call
    m.links = set(v.group(1).decode("latin1").strip() for v in
                  re.finditer(rb"^X-[\w-]*uuid\s*:\s*(\S+)", head[0], re.M | re.I))
    m.media = []
    if len(head) > 1 and b"m=audio" in head[1]:
        c = None
        for line in head[1].split(b"\n"):
            line = line.strip()
            if line.startswith(b"c=IN IP4 "):
                c = line[9:].decode("latin1").strip()
            elif line.startswith(b"m=audio ") and c:
                m.media.append((c, int(line.split()[1])))
    return m


def index_file(path, host):
    msgs, ra, partial = [], Reassembler(), {}
    for ts, lt, data in pcap_iter(path):
        p = decode(ts, lt, data)
        if p is None or p.proto not in (6, 17):
            continue
        fkey = (p.src, p.dst, p.ident)
        if p.mf or p.frag_off:
            r = ra.add(p)
            if not r:
                if p.frag_off == 0:
                    # first fragment alone already holds the SIP headers; the rest is often not
                    # captured (tcpdump "udp port" filter), so index it now and upgrade if it completes
                    m = parse_sip(ts, host, ip_s(p.src), ip_s(p.dst), p.sport, p.dport, p.payload)
                    if m:
                        partial[fkey] = len(msgs)
                        msgs.append(m)
                continue
            sport, dport, payload = r
        else:
            sport, dport, payload = p.sport, p.dport, p.payload
        m = parse_sip(ts, host, ip_s(p.src), ip_s(p.dst), sport, dport, payload)
        if m:
            if fkey in partial and (p.mf or p.frag_off):
                m.ts = msgs[partial[fkey]].ts
                msgs[partial.pop(fkey)] = m
            else:
                msgs.append(m)
    return msgs


class Dialog:
    def __init__(self, cid):
        self.cid = cid
        self.msgs = []
        self.links = set()

    @property
    def t0(self):
        return min(m.ts for m in self.msgs)

    @property
    def t1(self):
        return max(m.ts for m in self.msgs)

    def invite(self):
        return next((m for m in sorted(self.msgs, key=lambda x: x.ts) if m.method == "INVITE"), None)

    def final(self):
        """Final status of the INVITE transaction (max seen), 0 if none."""
        st = [m.status for m in self.msgs if m.status and m.status >= 200 and m.cseq == "INVITE"]
        return 200 if 200 in st else (max(st) if st else 0)

    def ended(self):
        if any(m.method in ("BYE", "CANCEL") for m in self.msgs):
            return True
        f = self.final()
        return f >= 300

    def pending(self):
        """INVITE got an answer (1xx/200) but no end yet -> worth looking further in time."""
        return (self.is_call() and not self.ended() and
                any(m.status and m.cseq == "INVITE" for m in self.msgs))

    def is_call(self):
        """Any message of an INVITE dialog (request, response or BYE of a call already set up)."""
        return any(m.cseq in ("INVITE", "BYE") for m in self.msgs)


def build_dialogs(msgs):
    ds = {}
    for m in msgs:
        d = ds.get(m.call_id)
        if d is None:
            d = ds[m.call_id] = Dialog(m.call_id)
        d.msgs.append(m)
        d.links |= m.links
    return ds


def group_dialogs(ds, seeds):
    """Expand seed Call-IDs to every dialog sharing an X-*uuid value with them."""
    by_link = collections.defaultdict(set)
    for d in ds.values():
        for l in d.links:
            by_link[l].add(d.cid)
    groups, seen = [], set()
    for s in seeds:
        if s in seen:
            continue
        comp, todo = set(), [s]
        while todo:
            c = todo.pop()
            if c in comp:
                continue
            comp.add(c)
            for l in ds[c].links:
                todo.extend(by_link[l] - comp)
        seen |= comp
        groups.append(sorted(comp, key=lambda c: ds[c].t0))
    return groups


def matches(d, a):
    if a.call_id and d.cid not in a.call_id:
        return False
    if a.icc_uuid and not (set(a.icc_uuid) & d.links):
        return False
    if a.number:
        users = set()
        for m in d.msgs:
            users.update((m.from_u, m.to_u, uri_user(m.ruri) if m.ruri else ""))
        if not any(n in u for n in a.number for u in users if u):
            return False
    if a.ip:
        ips = set()
        for m in d.msgs:
            ips.update((m.src, m.dst))
            ips.update(c for c, _ in m.media)
        if not set(a.ip) & ips:
            return False
    return d.is_call()


# ---------------------------------------------------------------- packet selection
PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)")


class CallSelector:
    def __init__(self, dialogs):
        self.cids = set(d.cid for d in dialogs)
        self.t0 = min(d.t0 for d in dialogs) - MEDIA_PAD[0]
        self.t1 = max(d.t1 for d in dialogs) + MEDIA_PAD[1]
        self.eps, self.ports = set(), set()
        for d in dialogs:
            for m in d.msgs:
                for ip, port in m.media:
                    for pt in (port, port + 1):          # RTP + RTCP
                        if PRIVATE.match(ip):
                            self.ports.add(pt)           # NATed SDP: match by port only
                        else:
                            self.eps.add((ip, pt))
        self.frags = set()

    def __call__(self, p):
        key = (p.src, p.dst, p.ident)
        if p.frag_off:
            return key in self.frags
        ok = False
        if SIP_START.match(p.payload):
            cid = hdr(p.payload.split(b"\r\n\r\n", 1)[0], b"Call-ID", b"i")
            ok = cid in self.cids
        elif p.proto == 17 and self.t0 <= p.ts <= self.t1:
            s, d = ip_s(p.src), ip_s(p.dst)
            ok = ((s, p.sport) in self.eps or (d, p.dport) in self.eps or
                  p.sport in self.ports or p.dport in self.ports)
        if ok and p.mf:
            self.frags.add(key)
        return ok


def window_selector(t0, t1):
    return lambda p: t0 <= p.ts <= t1


def write_merged(out, paths, select, dedup=True):
    """Stream-merge packets of all files by time, keep the selected ones, drop cross-host duplicates."""
    lts = set(pcap_header(p)[2] for p in paths if pcap_header(p))
    out_lt = lts.pop() if len(lts) == 1 else LINKTYPE_RAW

    def gen(path):
        for ts, lt, data in pcap_iter(path):
            p = decode(ts, lt, data)
            if p is None:
                continue
            if select(p):
                yield p

    recent = collections.OrderedDict()
    n = dup = 0
    proto_n = collections.Counter()
    first = last = None
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, out_lt))
        for p in heapq.merge(*(gen(x) for x in paths), key=lambda p: p.ts):
            if dedup:
                k = (p.src, p.dst, p.proto, p.ident, p.frag_off, p.sport, p.dport, zlib.crc32(p.payload))
                while recent and next(iter(recent.values())) < p.ts - DEDUP_WINDOW:
                    recent.popitem(last=False)
                if k in recent:
                    dup += 1
                    continue
                recent[k] = p.ts
            data = p.data if out_lt != LINKTYPE_RAW else p.data[p.ipo:]
            sec = int(p.ts)
            us = int(round((p.ts - sec) * 1e6))
            if us >= 1000000:
                sec, us = sec + 1, us - 1000000
            f.write(struct.pack("<IIII", sec, us, len(data), len(data)))
            f.write(data)
            n += 1
            first = p.ts if first is None else first
            last = p.ts
            proto_n["SIP" if SIP_START.match(p.payload) else ("UDP" if p.proto == 17 else str(p.proto))] += 1
    return n, dup, proto_n, first, last


# ---------------------------------------------------------------- main
def safe_name(s):
    return re.sub(r'[<>:"/\\|?*@\s]', "_", s)[:80]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="t_from", required=True, help="window start, UTC unless +HH:MM given")
    ap.add_argument("--to", dest="t_to", required=True, help="window end")
    ap.add_argument("--list", action="store_true", help="only list calls found in the window")
    ap.add_argument("--all", action="store_true", help="merge every packet of the window into one pcap")
    ap.add_argument("--call-id", action="append", default=[])
    ap.add_argument("--icc-uuid", action="append", default=[], help="X-icc_uuid (or any X-*uuid) value")
    ap.add_argument("--number", action="append", default=[], help="substring of From/To/R-URI user")
    ap.add_argument("--ip", action="append", default=[], help="signalling or media IP of the call")
    ap.add_argument("--bucket", action="append", help="bucket(s), default: %s" % " ".join(BUCKETS))
    ap.add_argument("--host", action="append", help="limit to host prefix(es) inside the buckets")
    ap.add_argument("--max-extend", type=float, default=120,
                    help="minutes the window may grow to reach INVITE/BYE of a matched call (default 120)")
    ap.add_argument("--no-dedup", action="store_true", help="keep copies of a packet captured on two hosts")
    ap.add_argument("--out-dir", default="calls")
    ap.add_argument("--cache", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "s3cache"),
                    help="where downloaded+unpacked dumps are kept")
    ap.add_argument("--profile")
    ap.add_argument("--region")
    a = ap.parse_args()

    t_from, t_to = parse_time(a.t_from), parse_time(a.t_to)
    if t_to <= t_from:
        raise SystemExit("--to must be after --from")
    has_filter = a.call_id or a.icc_uuid or a.number or a.ip
    if not (a.list or a.all or has_filter):
        raise SystemExit("give a filter (--call-id/--icc-uuid/--number/--ip), --list or --all")

    store = Store(a)
    local, index = {}, {}

    def load(w0, w1):
        items = [it for it in store.files(w0, w1) if it not in local]
        if items:
            print("downloading %d file(s) ..." % len(items), file=sys.stderr)
            local.update(store.fetch(items))
        for it in local:
            if it not in index:
                index[it] = index_file(local[it], it[1])

    print("window %s .. %s UTC" % (fmt_ts(t_from), fmt_ts(t_to)), file=sys.stderr)
    load(t_from, t_to)
    if not local:
        raise SystemExit("no dump files in this window")

    if a.all:
        paths = sorted(local[it] for it in local if it[3] <= t_to)
        out = os.path.join(a.out_dir, "window_%s_%s.pcap" % (
            fmt_ts(t_from).replace(" ", "_").replace(":", "-"), fmt_ts(t_to)[11:].replace(":", "-")))
        n, dup, pn, f0, f1 = write_merged(out, paths, window_selector(t_from, t_to), not a.no_dedup)
        print("%s: %d packets (%s), %d duplicates dropped" % (out, n, dict(pn), dup))
        return

    def current():
        msgs = [m for it, ms in index.items() for m in ms]
        return build_dialogs(msgs)

    ds = current()
    if a.list:
        calls = [d for d in ds.values() if d.is_call() and t_from <= d.t0 <= t_to]
        groups = group_dialogs(ds, [d.cid for d in sorted(calls, key=lambda d: d.t0)])
        print("%-19s %-6s %-5s %-16s %-22s %-22s %-38s %s" % (
            "start UTC", "dur", "final", "hosts", "from", "to", "Call-ID", "X-uuid"))
        for g in groups:
            for i, cid in enumerate(g):
                d = ds[cid]
                inv = d.invite() or min(d.msgs, key=lambda m: m.ts)
                hosts = ",".join(sorted(set(m.host for m in d.msgs)))
                print("%s%-19s %5.0fs %-5s %-16s %-22s %-22s %-38s %s" % (
                    "  " if i else "", fmt_ts(d.t0), d.t1 - d.t0, d.final() or "-", hosts[:16],
                    (inv.from_u if inv else "")[:22], (inv.to_u if inv else "")[:22], cid[:38],
                    ",".join(sorted(d.links))[:40]))
        print("%d call group(s)" % len(groups), file=sys.stderr)
        return

    # extend the window until each matched call has its INVITE and its end
    lo, hi = t_from, t_to
    lim_lo, lim_hi = t_from - a.max_extend * 60, t_to + a.max_extend * 60
    can_lo = can_hi = True
    while True:
        # only calls that overlap the requested window; extension just completes them
        seeds = [d.cid for d in sorted(ds.values(), key=lambda d: d.t0)
                 if d.t0 <= t_to and d.t1 >= t_from and matches(d, a)]
        if not seeds:
            raise SystemExit("no matching call in %s .. %s" % (fmt_ts(t_from), fmt_ts(t_to)))
        groups = group_dialogs(ds, seeds)
        if a.call_id or a.icc_uuid:
            # legs named explicitly belong to one call -> one pcap
            groups = [sorted(set(c for g in groups for c in g), key=lambda c: ds[c].t0)]
        cids = set(c for g in groups for c in g)
        need_lo = can_lo and any(ds[c].is_call() and not ds[c].invite() for c in cids)
        need_hi = can_hi and any(ds[c].pending() for c in cids)
        nlo = max(lim_lo, lo - EXTEND_STEP) if need_lo and lo > lim_lo else lo
        nhi = min(lim_hi, hi + EXTEND_STEP) if need_hi and hi < lim_hi else hi
        if (nlo, nhi) == (lo, hi):
            break
        print("call not complete, extending window to %s .. %s" % (fmt_ts(nlo), fmt_ts(nhi)), file=sys.stderr)
        before = {c: set(m.ts for m in ds[c].msgs) for c in cids}
        t_min, t_max = min(ds[c].t0 for c in cids), max(ds[c].t1 for c in cids)
        lo, hi = nlo, nhi
        load(lo, hi)
        ds = current()
        # a step that brought nothing new for these legs (e.g. INVITE sent over TLS/WS, never
        # captured) stops growing the window in that direction
        new = [m.ts for c in cids for m in ds[c].msgs if m.ts not in before[c]]
        can_lo = can_lo and any(t < t_min for t in new)
        can_hi = can_hi and any(t > t_max for t in new)

    os.makedirs(a.out_dir, exist_ok=True)
    for g in groups:
        dl = [ds[c] for c in g]
        sel = CallSelector(dl)
        # a file starting up to 10 min before the call may still hold its first packets
        paths = sorted(local[it] for it in local if sel.t0 - 600 <= it[3] <= sel.t1)
        main_d = next((d for d in dl if d.invite()), dl[0])
        name = sorted(set().union(*(d.links for d in dl)) or {main_d.cid})[0]
        out = os.path.join(a.out_dir, "%s_%s.pcap" % (
            fmt_ts(main_d.t0).replace(" ", "_").replace(":", "-"), safe_name(name)))
        n, dup, pn, f0, f1 = write_merged(out, paths, sel, not a.no_dedup)
        inv = main_d.invite()
        print("\n%s" % out)
        print("  %s -> %s  final=%s  %s .. %s (%.0fs)" % (
            inv.from_u if inv else "?", inv.to_u if inv else "?", main_d.final() or "-",
            fmt_ts(min(d.t0 for d in dl)), fmt_ts(max(d.t1 for d in dl)),
            max(d.t1 for d in dl) - min(d.t0 for d in dl)))
        for d in dl:
            print("  leg %-40s hosts=%s msgs=%d ended=%s" % (
                d.cid[:40], ",".join(sorted(set(m.host for m in d.msgs))), len(d.msgs), d.ended()))
        print("  packets=%d %s, duplicates dropped=%d" % (n, dict(pn), dup))
        if not any(ds[c].ended() for c in g):
            print("  WARNING: no BYE/CANCEL/final error found within --max-extend")


if __name__ == "__main__":
    main()
