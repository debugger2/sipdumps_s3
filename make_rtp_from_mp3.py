#!/usr/bin/env python3
import struct, socket, sys

def pcm16_to_alaw(sample):
    if sample >= 0:
        sign = 0x00
    else:
        sign = 0x80
        sample = -sample
    if sample > 32635:
        sample = 32635
    sample >>= 4
    if sample < 32:
        sample = 1
    segment = (sample >> 4) & 0x07
    if segment == 0:
        segment = 1
    mantissa = (sample - (segment << 4)) & 0x0F
    alaw = (segment << 4) | mantissa
    return sign | (alaw ^ 0x55)

def pcm16_to_ulaw(sample):
    if sample >= 0:
        sign = 0x80
    else:
        sign = 0x00
        sample = -sample
    if sample > 8159:
        sample = 8159
    sample += 132
    exponent = 0
    exp_mask = 0x4000
    while (sample & exp_mask) == 0 and exponent < 7:
        exponent += 1
        exp_mask >>= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    ulaw = ~(sign | (exponent << 4) | mantissa)
    return ulaw & 0xFF

def checksum(b):
    if len(b) % 2 == 1:
        b += b'\x00'
    s = 0
    for k in range(0, len(b), 2):
        s += ((b[k] << 8) | b[k+1]) & 0xFFFF
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def get_first_ts(pcap):
    d = open(pcap,'rb').read()
    if len(d) < 24:
        return 1771700000, 0
    magic = d[:4]
    endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
    pos = 24
    if pos+16 <= len(d):
        sec,us,incl,orig = struct.unpack(endian+'IIII', d[pos:pos+16])
        return sec, us
    return 1771700000, 0

def main():
    raw_path = sys.argv[1]
    sip_pcap = sys.argv[2]
    out_path = sys.argv[3]
    with open(raw_path, 'rb') as f:
        pcm = f.read()
    
    base_sec, base_us = get_first_ts(sip_pcap)
    base_ts = base_sec + base_us / 1e6 + 7.0  # ~к моменту когда появился медиа от провайдера
    
    packets = []
    frame_size = 160
    i = 0; pkt_idx = 0
    seq_in = 10000; seq_out = 20000
    ssrc_in = 0x12345678; ssrc_out = 0x87654321
    ts_in = 0; ts_out = 0
    while i + frame_size*2 <= len(pcm) and pkt_idx < 7660:
        # provider 38.91.100.151:27546 -> PBX 200.25.27.22:24922 PCMA
        alaw_list = []
        for j in range(frame_size):
            s = struct.unpack('<h', pcm[i+j*2:i+j*2+2])[0]
            alaw_list.append(pcm16_to_alaw(s) & 0xFF)
        rtp = bytearray([0x80, 8]) + struct.pack('>H', seq_in) + struct.pack('>I', ts_in) + struct.pack('>I', ssrc_in)
        seq_in += 1; ts_in += 160
        rtp_pkt = bytes(rtp) + bytes(alaw_list)
        ts = base_ts + pkt_idx * 0.02
        eth = bytes([0,1,2,3,4,5,6,7,8,9,10,11,0x08,0x00])
        ip = bytearray(20); ip[0]=0x45; ip[1]=0x00; tot=28+len(rtp_pkt); ip[2:4]=struct.pack('>H',tot); ip[8]=64; ip[9]=17
        ip[12:16]=socket.inet_aton('38.91.100.151'); ip[16:20]=socket.inet_aton('200.25.27.22')
        ip[10:12]=struct.pack('>H', checksum(bytes(ip)))
        udp = bytearray(8); udp[0:2]=struct.pack('>H',27546); udp[2:4]=struct.pack('>H',24922); udp[4:6]=struct.pack('>H',8+len(rtp_pkt))
        udp_p = bytes(udp)+rtp_pkt
        ip2 = bytearray(ip); ip2[10:12]=bytes([0,0]); ip2[10:12]=struct.pack('>H', checksum(bytes(ip2)))
        sec = int(ts); usec = int((ts-sec)*1e6)
        if usec < 0: usec = 0
        if usec >= 1000000: sec += 1; usec -= 1000000
        packets.append((sec, usec, bytes(eth)+bytes(ip2)+udp_p))
        # PBX -> provider PCMU
        ulaw_list = []
        for j in range(frame_size):
            s = struct.unpack('<h', pcm[i+j*2:i+j*2+2])[0]
            ulaw_list.append(pcm16_to_ulaw(s) & 0xFF)
        rtp2 = bytearray([0x80, 0]) + struct.pack('>H', seq_out) + struct.pack('>I', ts_out) + struct.pack('>I', ssrc_out)
        seq_out += 1; ts_out += 160
        rtp_pkt2 = bytes(rtp2) + bytes(ulaw_list)
        ts2 = base_ts + pkt_idx * 0.02 + 0.01
        eth2 = bytes([0,1,2,3,4,5,6,7,8,9,10,11,0x08,0x00])
        ip3 = bytearray(20); ip3[0]=0x45; ip3[1]=0x00; tot3=28+len(rtp_pkt2); ip3[2:4]=struct.pack('>H',tot3); ip3[8]=64; ip3[9]=17
        ip3[12:16]=socket.inet_aton('200.25.27.22'); ip3[16:20]=socket.inet_aton('38.91.100.151')
        ip3[10:12]=struct.pack('>H', checksum(bytes(ip3)))
        udp3 = bytearray(8); udp3[0:2]=struct.pack('>H',24922); udp3[2:4]=struct.pack('>H',27546); udp3[4:6]=struct.pack('>H',8+len(rtp_pkt2))
        udp_p3 = bytes(udp3)+rtp_pkt2
        ip4 = bytearray(ip3); ip4[10:12]=bytes([0,0]); ip4[10:12]=struct.pack('>H', checksum(bytes(ip4)))
        sec2 = int(ts2); usec2 = int((ts2-sec2)*1e6)
        if usec2 < 0: usec2 = 0
        if usec2 >= 1000000: sec2 += 1; usec2 -= 1000000
        packets.append((sec2, usec2, bytes(eth2)+bytes(ip4)+udp_p3))
        i += frame_size*2; pkt_idx += 1
    
    d = open(sip_pcap,'rb').read()
    magic = d[:4]
    endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
    out_hdr = bytearray(d[:24])
    def parse(p):
        res=[]
        pos=24
        while pos+16<=len(p):
            sec,us,incl,orig=struct.unpack(endian+'IIII',p[pos:pos+16]); pos+=16
            raw=p[pos:pos+incl]; pos+=incl
            res.append((sec,us,raw))
        return res
    allp = parse(d) + packets
    allp.sort(key=lambda x:(x[0],x[1]))
    out = bytearray(out_hdr)
    for sec,us,raw in allp:
        out += struct.pack(endian+'IIII',sec,us,len(raw),len(raw))+raw
    open(out_path,'wb').write(bytes(out))
    print('done', len(allp))

if __name__=='__main__':
    main()
