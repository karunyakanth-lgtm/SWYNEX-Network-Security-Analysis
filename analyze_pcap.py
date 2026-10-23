#!/usr/bin/env python3
"""
SWYNEX Task 2 - Defensive PCAP analyzer (standard library only).

Reads a capture file (.pcap or .pcapng, Ethernet link type) saved from
Wireshark, tcpdump or similar. Use only your own lab traffic or an approved
sample capture. It reports the protocol mix, top talkers, DNS activity and
common security concerns:

  - cleartext protocols (HTTP, FTP, Telnet, POP3, IMAP, SMTP)
  - possible credentials sent in cleartext
  - TCP SYN scan behaviour (many ports probed by one source)
  - ARP spoofing indicators (one IP claimed by several MAC addresses)
  - high-volume ICMP
  - unusually long DNS labels (possible tunnelling)

Usage:
    python analyze_pcap.py capture.pcap [-o findings.md]
"""
import argparse
import collections
import re
import socket
import struct
import sys

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP",
                   110: "POP3", 143: "IMAP"}
CRED_PATTERN = re.compile(
    rb"(password=|passwd=|pwd=|^USER |^PASS |Authorization: Basic)",
    re.I | re.M)
SCAN_PORT_THRESHOLD = 15
ICMP_THRESHOLD = 50
DNS_LABEL_LEN_THRESHOLD = 40


# ----------------------------------------------------------------- readers
def read_packets(path):
    """Yield raw Ethernet frames from a pcap or pcapng file."""
    with open(path, "rb") as fh:
        data = fh.read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                 b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        yield from _read_pcap(data)
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data)
    else:
        raise ValueError("Not a pcap/pcapng file (unknown magic number)")


def _read_pcap(data):
    if len(data) < 24:
        raise ValueError("Truncated pcap global header")
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1:
        raise ValueError(f"Unsupported link type {linktype}; expected Ethernet (1)")
    pos = 24
    while pos < len(data):
        if len(data) - pos < 16:
            raise ValueError("Truncated pcap packet header")
        _, _, incl, orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        if incl > len(data) - pos:
            raise ValueError("Truncated pcap packet data")
        if incl > orig:
            raise ValueError("Invalid pcap packet: captured length exceeds original length")
        yield data[pos:pos + incl]
        pos += incl


def _read_pcapng(data):
    pos, endian = 0, "<"
    interface_linktypes = []
    while pos < len(data):
        if len(data) - pos < 12:
            raise ValueError("Truncated pcapng block header")
        if data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":  # section header
            if len(data) - pos < 28:
                raise ValueError("Truncated pcapng section header")
            bom = data[pos + 8:pos + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("Invalid pcapng byte-order magic")
            interface_linktypes = []
        btype, blen = struct.unpack(endian + "II", data[pos:pos + 8])
        if blen < 12 or blen % 4:
            raise ValueError("Invalid pcapng block length")
        if pos + blen > len(data):
            raise ValueError("Truncated pcapng block")
        trailing_len = struct.unpack(endian + "I", data[pos + blen - 4:pos + blen])[0]
        if trailing_len != blen:
            raise ValueError("Mismatched pcapng block lengths")
        body = data[pos + 8:pos + blen - 4]
        if btype == 1:  # interface description block
            if len(body) < 8:
                raise ValueError("Truncated pcapng interface description")
            linktype = struct.unpack(endian + "H", body[:2])[0]
            if linktype != 1:
                raise ValueError(f"Unsupported pcapng link type {linktype}; expected Ethernet (1)")
            interface_linktypes.append(linktype)
        elif btype == 6:  # enhanced packet block
            if len(body) < 20:
                raise ValueError("Truncated pcapng enhanced packet block")
            interface_id, = struct.unpack(endian + "I", body[:4])
            cap_len, = struct.unpack(endian + "I", body[12:16])
            if interface_id >= len(interface_linktypes):
                raise ValueError(f"Unknown pcapng interface ID {interface_id}")
            if cap_len > len(body) - 20:
                raise ValueError("Truncated pcapng packet data")
            yield body[20:20 + cap_len]
        elif btype == 3:  # simple packet block (implicitly interface 0)
            if len(body) < 4:
                raise ValueError("Truncated pcapng simple packet block")
            if not interface_linktypes:
                raise ValueError("pcapng packet appears before an interface description")
            orig_len, = struct.unpack(endian + "I", body[:4])
            cap_len = min(orig_len, len(body) - 4)
            yield body[4:4 + cap_len]
        pos += blen

# ----------------------------------------------------------------- decoding
def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def analyze(path):
    total = 0
    proto = collections.Counter()
    talkers = collections.Counter()
    dns_queries = collections.Counter()
    cleartext = collections.Counter()
    cred_hits = set()
    syn_ports = collections.defaultdict(set)
    arp_map = collections.defaultdict(set)
    icmp_src = collections.Counter()
    long_dns = set()

    for frame in read_packets(path):
        total += 1
        if len(frame) < 14:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]

        if ethertype == 0x0806 and len(payload) >= 28:        # ARP
            proto["ARP"] += 1
            op = struct.unpack("!H", payload[6:8])[0]
            if op == 2:
                arp_map[socket.inet_ntoa(payload[14:18])].add(mac(payload[8:14]))
            continue
        if ethertype != 0x0800 or len(payload) < 20:          # IPv4 only
            proto["Other"] += 1
            continue

        # Validate the IPv4 header and respect the declared IP packet length.
        if payload[0] >> 4 != 4:
            proto["Other"] += 1
            continue
        ihl = (payload[0] & 0x0F) * 4
        total_len = struct.unpack("!H", payload[2:4])[0]
        if ihl < 20 or total_len < ihl or ihl > len(payload) or total_len > len(payload):
            continue
        # Non-initial IPv4 fragments do not start with a transport header.
        frag_field = struct.unpack("!H", payload[6:8])[0]
        if frag_field & 0x1FFF:
            proto["Other"] += 1
            continue
        ip_packet = payload[:total_len]
        ip_proto = ip_packet[9]
        src = socket.inet_ntoa(ip_packet[12:16])
        talkers[src] += 1
        l4 = ip_packet[ihl:]

        if ip_proto == 6 and len(l4) >= 20:                   # TCP
            proto["TCP"] += 1
            sport, dport = struct.unpack("!HH", l4[:4])
            flags = l4[13]
            offset = (l4[12] >> 4) * 4
            if offset < 20 or offset > len(l4):
                continue
            if flags & 0x12 == 0x02:                          # SYN, no ACK
                syn_ports[src].add(dport)
            body = l4[offset:]
            if body:  # only count segments that actually carry data
                for port in (sport, dport):
                    if port in CLEARTEXT_PORTS:
                        cleartext[CLEARTEXT_PORTS[port]] += 1
                        break
                if CRED_PATTERN.search(body):
                    dst = socket.inet_ntoa(ip_packet[16:20])
                    cred_hits.add((src, dst, dport))
        elif ip_proto == 17 and len(l4) >= 8:                 # UDP
            proto["UDP"] += 1
            sport, dport = struct.unpack("!HH", l4[:4])
            if 53 in (sport, dport):
                name = parse_dns_qname(l4[8:])
                if name:
                    proto["DNS"] += 1
                    dns_queries[name] += 1
                    if any(len(lbl) > DNS_LABEL_LEN_THRESHOLD
                           for lbl in name.split(".")):
                        long_dns.add(name)
        elif ip_proto == 1:                                   # ICMP
            proto["ICMP"] += 1
            icmp_src[src] += 1
        else:
            proto["Other"] += 1

    findings = []
    for name, n in cleartext.items():
        findings.append(("Medium", f"Cleartext {name} traffic ({n} packets)",
                         "Replace with an encrypted equivalent (HTTPS, SFTP, SSH, TLS-enabled mail)."))
    for src, dst, port in sorted(cred_hits):
        findings.append(("High", f"Possible credentials in cleartext: {src} -> {dst}:{port}",
                         "Rotate the affected credentials and enforce TLS."))
    for src, ports in syn_ports.items():
        if len(ports) >= SCAN_PORT_THRESHOLD:
            findings.append(("High", f"Possible port scan from {src} ({len(ports)} distinct ports probed)",
                             "Confirm the source is authorised; rate-limit or block at the firewall; review IDS alerts."))
    for ip, macs in arp_map.items():
        if len(macs) > 1:
            findings.append(("High", f"ARP anomaly: {ip} claimed by {len(macs)} MAC addresses {sorted(macs)}",
                             "Possible ARP spoofing. Enable Dynamic ARP Inspection or static ARP for critical hosts."))
    for ip, n in icmp_src.items():
        if n >= ICMP_THRESHOLD:
            findings.append(("Low", f"High ICMP volume from {ip} ({n} packets)",
                             "Check for ping sweeps or flooding; rate-limit ICMP."))
    for name in sorted(long_dns):
        findings.append(("Medium", f"Unusually long DNS label: {name[:60]}",
                         "Possible DNS tunnelling or DGA; inspect the domain and the querying host."))
    return total, proto, talkers, dns_queries, findings


def parse_dns_qname(udp_payload):
    """Return the first query name of a DNS message, or None."""
    if len(udp_payload) < 13:
        return None
    labels, pos = [], 12
    while pos < len(udp_payload):
        n = udp_payload[pos]
        if n == 0:
            break
        if n & 0xC0 or pos + 1 + n > len(udp_payload):
            return None
        labels.append(udp_payload[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels) or None


# ----------------------------------------------------------------- report
def render(path, total, proto, talkers, dns_queries, findings):
    out = [f"# Findings for `{path}`", "", f"Total packets: **{total}**", "",
           "## Protocol distribution", "", "| Protocol | Packets |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in proto.most_common()]
    out += ["", "## Top talkers (source IP)", "", "| IP | Packets |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in talkers.most_common(5)]
    out += ["", "## Most queried DNS names", "", "| Name | Queries |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in dns_queries.most_common(5)]
    out += ["", "## Security observations", ""]
    if findings:
        order = {"High": 0, "Medium": 1, "Low": 2}
        out += ["| Severity | Observation | Recommended action |", "|---|---|---|"]
        for sev, obs, rec in sorted(findings, key=lambda f: order[f[0]]):
            out.append(f"| {sev} | {obs} | {rec} |")
    else:
        out.append("No issues matched the built-in checks.")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", help="capture file (.pcap or .pcapng)")
    ap.add_argument("-o", "--output", help="write markdown findings to this file")
    args = ap.parse_args()
    report = render(args.pcap, *analyze(args.pcap))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Wrote {args.output}")
    else:
        sys.stdout.write(report)


if __name__ == "__main__":
    main()
