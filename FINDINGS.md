# Findings: aa.pcapng

Capture of my own Kali Linux lab VM (VirtualBox NAT, VM address `10.0.2.15`), 964 packets, analysed with Wireshark and `analyze_pcap.py`.

## Summary

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Cleartext HTTP (port 80) traffic | Medium | Reported by analyzer (1 packet); confirm with the Wireshark `http` filter |
| 2 | Failed HTTP connection to neverssl.com (SYN retransmissions, then RST) | Info | Confirmed in Wireshark (packets 938 to 964) |
| 3 | IPv6 traffic not decoded by the analyzer (11 packets) | Info | Confirmed in Wireshark (ICMPv6, IPv6 TCP and DNS) |
| 4 | Duplicate DNS response and ICMP "Port unreachable" | Info | Confirmed in Wireshark (packets 948 to 950) |
| 5 | Large UDP flow to `162.159.138.232` (491 packets) | Info | Confirm protocol with `ip.addr == 162.159.138.232` |

No port scans, ARP spoofing, credentials in cleartext, ICMP flooding or DNS tunnelling were detected.

## Finding 1: Cleartext HTTP traffic (Medium)

- **Evidence:** the analyzer counted 1 TCP packet carrying data on port 80. Screenshot: `screenshots/http-filter.png`.
- **Risk:** HTTP is unencrypted. Anyone on the network path can read or change the content, including cookies and form data.
- **How to verify:** Wireshark filter `http` (or `tcp.port == 80 && tcp.len > 0`). Record the destination and the request line here: `[fill in]`.
- **Recommendation:** use HTTPS only, turn on the browser's HTTPS-only mode, use a VPN on untrusted networks, and add HSTS on servers.

## Finding 2: Failed connection to neverssl.com (Info)

- **Evidence:** DNS resolved `neverssl.com` to `34.223.124.45`. The VM sent a TCP SYN to port 80 and retransmitted it five times (packets 938 to 957) with no SYN-ACK. At packet 964 the server answered `RST, ACK` and the connection closed. No HTTP request was sent.
- **Meaning:** a connectivity problem on the lab network, not an attack. A parallel IPv6 attempt also failed with ICMPv6 "No route to destination" (packet 946).
- **Verification filters:** `ip.addr == 34.223.124.45`, `tcp.analysis.retransmission`
- **Recommendation:** for monitoring, repeated SYN retransmissions to one host are a useful signal for outages or filtering.

## Finding 3: IPv6 traffic (Info)

- **Evidence:** ICMPv6 neighbor solicitation and advertisement, router advertisement from `52:54:00:12:35:00` (the VirtualBox NAT gateway), multicast listener reports, and IPv6 DNS and TCP.
- **Meaning:** normal for a modern network. The analyzer decodes IPv4 only, so these appear as "Other" (11 packets).
- **Recommendation:** if IPv6 is not needed on a network, disable it or apply the same firewall and monitoring rules as IPv4, because unmonitored IPv6 can hide traffic.

## Finding 4: Duplicate DNS response (Info)

- **Evidence:** the AAAA response for `neverssl.com` arrived twice (packets 948 and 949) and the VM answered with ICMP "Destination unreachable (Port unreachable)" (packet 950).
- **Meaning:** harmless here, caused by a duplicated reply in the virtual network. In general, unexpected duplicate or unsolicited DNS responses can indicate DNS spoofing attempts, so they are worth checking.
- **Recommendation:** use DNSSEC-validating resolvers and monitor for DNS responses that do not match a request.

## Finding 5: Large UDP flow (Info)

- **Evidence:** `162.159.138.232` sent 491 of 964 packets, mostly UDP. The DNS names looked up include `discord.gg` and `discord.com`.
- **Assessment:** `[after checking in Wireshark, state what it is, for example QUIC or Discord voice/video]`
- **Recommendation:** baseline normal traffic per host and alert on large flows to unfamiliar destinations.

## Checks that found nothing

| Check | Result |
|---|---|
| Credentials in cleartext | None |
| TCP SYN port scan (15+ ports from one source) | None |
| ARP spoofing (one IP, several MACs) | None (4 ARP packets, one conflict-free gateway reply) |
| ICMP flood (50+ packets from one source) | None (10 ICMP packets, all pings to `8.8.8.8` and one port-unreachable) |
| Long DNS labels (tunnelling) | None |

## Method

1. Captured on `eth0` in Wireshark and saved as `aa.pcapng`.
2. Ran `python3 analyze_pcap.py aa.pcapng -o my_findings.md`.
3. Confirmed the results manually in Wireshark with display filters.

## Limitations

- Single machine, short capture.
- Most traffic is encrypted, so only metadata (addresses, ports, DNS names) can be analysed.
- The analyzer decodes IPv4 over Ethernet only; thresholds are simple and findings are indicators, not proof.
