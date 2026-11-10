"""Build a full pcap (SIP + RTP) from a SIP-only Homer export and a FreeSWITCH
stereo recording (mp3/wav). Left channel = outgoing (FS -> remote),
right channel = incoming (remote -> FS).

Usage: python build_from_recording.py <sip.pcap> <recording.mp3> [out.pcap]
         [--offset SEC]   mp3 t=0 relative to first INVITE (default 0)
         [--onset SEC]    mp3 time where remote media starts (default: auto)
"""
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np

FFMPEG = r"C:\GIT\pcap_merge\tools\ffmpeg.exe"
RATE = 8000
PTIME = 0.02
SPF = int(RATE * PTIME)  # samples per frame


# ---------- pcap io ----------
def read_pcap(path):
    d = Path(path).read_bytes()
    magic = struct.unpack('<I', d[:4])[0]
    assert magic == 0xa1b2c3d4, 'expect little-endian usec pcap'
    linktype = struct.unpack('<I', d[20:24])[0]
    assert linktype == 1, 'expect Ethernet'
    pkts, off = [], 24
    while off < len(d):
        ts, us, cl, ol = struct.unpack('<IIII', d[off:off + 16])
        pkts.append((ts + us / 1e6, d[off + 16:off + 16 + cl]))
        off += 16 + cl
    return d[:24], pkts


def write_pcap(path, hdr, pkts):
    with open(path, 'wb') as f:
        f.write(hdr)
        for t, p in pkts:
            sec = int(t)
            us = int(round((t - sec) * 1e6))
            if us >= 1000000:
                sec, us = sec + 1, us - 1000000
            f.write(struct.pack('<IIII', sec, us, len(p), len(p)))
            f.write(p)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip2b(ip):
    return bytes(int(x) for x in ip.split('.'))


def udp_frame(eth, src, sport, dst, dport, payload, ttl, ident):
    ulen = 8 + len(payload)
    pseudo = ip2b(src) + ip2b(dst) + struct.pack('!BBH', 0, 17, ulen)
    uh = struct.pack('!HHHH', sport, dport, ulen, 0)
    uc = csum(pseudo + uh + payload) or 0xffff
    uh = struct.pack('!HHHH', sport, dport, ulen, uc)
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + ulen, ident, 0, ttl, 17, 0,
                      ip2b(src), ip2b(dst))
    iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
    return eth + iph + uh + payload


# ---------- SIP / SDP ----------
def sip_of(p):
    o = 14
    ihl = (p[o] & 15) * 4
    return p[o + ihl + 8:].decode('latin1', 'replace')


def parse_sdp(msg):
    body = msg.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in msg else ''
    c = re.search(r'^c=IN IP4 (\S+)', body, re.M)
    m = re.search(r'^m=audio (\d+) RTP/AVP ([\d ]+)', body, re.M)
    if not (c and m):
        return None
    return c.group(1), int(m.group(1)), [int(x) for x in m.group(2).split()]


# ---------- audio ----------
def load_audio(path):
    raw = subprocess.run([FFMPEG, '-hide_banner', '-loglevel', 'error', '-i', str(path),
                          '-ac', '2', '-ar', str(RATE), '-f', 's16le', '-'],
                         check=True, stdout=subprocess.PIPE).stdout
    return np.frombuffer(raw, dtype='<i2').reshape(-1, 2)


def ulaw(x):
    x = x.astype(np.int32)
    sign = np.where(x < 0, 0x80, 0)
    x = np.minimum(np.abs(x), 32635) + 0x84
    exp = np.floor(np.log2(x)).astype(np.int32) - 7
    exp = np.clip(exp, 0, 7)
    mant = (x >> (exp + 3)) & 0x0f
    return (~(sign | (exp << 4) | mant) & 0xff).astype(np.uint8)


def alaw(x):
    x = x.astype(np.int32) >> 3
    sign = np.where(x >= 0, 0x80, 0)
    x = np.minimum(np.where(x >= 0, x, -x - 1), 0xfff)
    exp = np.where(x >= 32, np.floor(np.log2(np.maximum(x, 1))).astype(np.int32) - 4, 0)
    mant = np.where(exp == 0, x >> 1, x >> exp) & 0x0f
    return ((sign | (exp << 4) | mant) ^ 0x55).astype(np.uint8)


def rtp_stream(enc, first_frame, nframes, t0, pt, rng, jitter):
    ssrc = rng.getrandbits(32)
    seq = rng.randrange(0, 65536)
    ts = rng.getrandbits(32)
    out = []
    for i, k in enumerate(range(first_frame, nframes)):
        hdr = struct.pack('!BBHII', 0x80, pt | (0x80 if i == 0 else 0),
                          (seq + i) & 0xffff, (ts + i * SPF) & 0xffffffff, ssrc)
        t = t0 + (k + 1) * PTIME + rng.uniform(0, jitter)
        out.append((t, hdr + enc[k * SPF:(k + 1) * SPF].tobytes()))
    return out, ssrc


def main():
    args = sys.argv[1:]
    opts = {}
    for name in ('--offset', '--onset'):
        if name in args:
            i = args.index(name)
            opts[name] = float(args[i + 1])
            del args[i:i + 2]
    sip_path, rec_path = Path(args[0]), Path(args[1])
    out = Path(args[2]) if len(args) > 2 else sip_path.with_name(sip_path.stem + '_full.pcap')

    hdr, pkts = read_pcap(sip_path)
    eth = pkts[0][1][:14]
    ttl = pkts[0][1][14 + 8]
    invite_ts = None
    offer = answer = None
    early_ts = answer_ts = None
    for t, p in pkts:
        m = sip_of(p)
        first = m.split('\r\n', 1)[0]
        sdp = parse_sdp(m)
        if first.startswith('INVITE') and invite_ts is None:
            invite_ts, offer = t, sdp
        elif first.startswith('SIP/2.0 18') and sdp and early_ts is None:
            early_ts, answer = t, sdp
        elif first.startswith('SIP/2.0 200') and 'INVITE' in m and answer_ts is None:
            answer_ts, answer = t, sdp or answer
    assert offer and answer, 'no SDP offer/answer'
    pt = next(x for x in answer[2] if x in offer[2] and x in (0, 8))
    media_ts = early_ts or answer_ts
    print('offer  (local) %s:%d' % offer[:2])
    print('answer (remote) %s:%d  pt=%d' % (answer[0], answer[1], pt))

    audio = load_audio(rec_path)
    nframes = len(audio) // SPF
    t0 = invite_ts + opts.get('--offset', 0.0)
    enc = (ulaw if pt == 0 else alaw)(audio)
    out_l, in_r = enc[:, 0].copy(), enc[:, 1].copy()

    # remote media onset: first non-digital-silence sample after the SIP 18x/200
    onset = opts.get('--onset')
    if onset is None:
        r = np.abs(audio[:, 1].astype(np.int32))
        start = int((media_ts - t0) * RATE)
        nz = np.nonzero(r[start:] > 2)[0]
        onset = (start + (nz[0] if len(nz) else 0)) / RATE
    first_out = int(np.ceil((media_ts - t0) / PTIME))
    first_in = int(onset / PTIME)
    print('recording %.1fs, %d frames; out from %.2fs, in from %.2fs (mp3 time)'
          % (len(audio) / RATE, nframes, first_out * PTIME, first_in * PTIME))

    rng = random.Random(sip_path.name)
    lip, lport = offer[:2]
    rip, rport = answer[:2]
    o_pkts, o_ssrc = rtp_stream(out_l, first_out, nframes, t0, pt, rng, 0.0015)
    i_pkts, i_ssrc = rtp_stream(in_r, first_in, nframes, t0, pt, rng, 0.004)
    rtp = []
    ident = rng.randrange(65536)
    for t, pl in o_pkts:
        ident = (ident + 1) & 0xffff
        rtp.append((t, udp_frame(eth, lip, lport, rip, rport, pl, 64, ident)))
    for t, pl in i_pkts:
        rtp.append((t, udp_frame(eth, rip, rport, lip, lport, pl, ttl, 0)))

    allp = sorted(pkts + rtp, key=lambda x: x[0])
    write_pcap(out, hdr, allp)
    print('ssrc out=0x%08x in=0x%08x' % (o_ssrc, i_ssrc))
    print('wrote %s: %d SIP + %d RTP packets' % (out, len(pkts), len(rtp)))


if __name__ == '__main__':
    main()
