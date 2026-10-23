#!/usr/bin/env python3
"""
Generate a small SYNTHETIC lab capture (sample_lab_traffic.pcap) so the
analyzer can be tested without real network data. Standard library only.

All hosts are fictional private addresses (192.168.56.0/24). Nothing here
touches a real network: the script only writes a file.
"""
import socket
import struct

OUT = "sample_lab_traffic.pcap"
t = [1760000000]  # fake timestamps


def eth(dst, src, ethertype, payload):
    return bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) \
        + struct.pack("!H", ethertype) + payload


def ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64,
                      proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def tcp(sport, dport, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0) + data


def udp(sport, dport, data):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def dns_query(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def arp_reply(ip_addr, mac_addr):
    m = bytes.fromhex(mac_addr.replace(":", ""))
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + m + socket.inet_aton(ip_addr) \
        + m + socket.inet_aton(ip_addr)


MAC = {"client": "aa:aa:aa:00:00:01", "web": "aa:aa:aa:00:00:02",
       "gw": "aa:aa:aa:00:00:fe", "attacker": "aa:aa:aa:00:00:66"}
CLIENT, WEB, GW, ATTACKER = "192.168.56.10", "192.168.56.20", "192.168.56.1", "192.168.56.66"

frames = []


def add(f):
    frames.append(f)


# 1. Normal DNS lookups
for name in ["example.test", "lab.example.test", "example.test"]:
    add(eth(MAC["gw"], MAC["client"], 0x0800,
            ip(CLIENT, GW, 17, udp(40000, 53, dns_query(name)))))

# 2. Cleartext HTTP login form (credentials in the lab web app)
http = (b"POST /login HTTP/1.1\r\nHost: lab.example.test\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"username=student&password=LabOnly123")
add(eth(MAC["web"], MAC["client"], 0x0800, ip(CLIENT, WEB, 6, tcp(50000, 80, 0x18, http))))

# 3. Cleartext FTP login
add(eth(MAC["web"], MAC["client"], 0x0800, ip(CLIENT, WEB, 6, tcp(50001, 21, 0x18, b"USER labuser\r\n"))))
add(eth(MAC["web"], MAC["client"], 0x0800, ip(CLIENT, WEB, 6, tcp(50001, 21, 0x18, b"PASS labpass\r\n"))))

# 4. SYN scan from a lab "attacker" VM across 30 ports
for port in range(1, 31):
    add(eth(MAC["web"], MAC["attacker"], 0x0800, ip(ATTACKER, WEB, 6, tcp(45000, port, 0x02))))

# 5. ARP: the lab attacker claims the gateway's IP
add(eth("ff:ff:ff:ff:ff:ff", MAC["gw"], 0x0806, arp_reply(GW, MAC["gw"])))
add(eth("ff:ff:ff:ff:ff:ff", MAC["attacker"], 0x0806, arp_reply(GW, MAC["attacker"])))

# 6. Suspiciously long DNS label (tunnelling-style)
long_name = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6.tunnel.example.test"
add(eth(MAC["gw"], MAC["client"], 0x0800, ip(CLIENT, GW, 17, udp(40001, 53, dns_query(long_name)))))

with open(OUT, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, f in enumerate(frames):
        fh.write(struct.pack("<IIII", 1760000000 + i, 0, len(f), len(f)))
        fh.write(f)
print(f"Wrote {OUT} with {len(frames)} synthetic packets")
