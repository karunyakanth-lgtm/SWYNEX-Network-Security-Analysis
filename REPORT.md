# Defensive Network Traffic Analysis Report

**Author:** [Your name]
**Date:** 23 October 2026
**Internship task:** SWYNEX Technologies, Task 2 (Network Security Analysis)

## 1. Scope and environment

- **Capture source:** my own lab traffic, captured in my own Kali Linux virtual machine. No third-party networks or systems were targeted.
- **Lab setup:** Kali Linux VM in VirtualBox using NAT networking. The VM's address is `10.0.2.15`. The upstream gateway seen in the capture is `192.168.31.1`.
- **Tools:** Wireshark (capture and manual verification) and `analyze_pcap.py` (a Python script written for this task that summarises a capture and flags common security concerns).
- **Capture file:** `aa.pcapng`, 964 packets.
- **Activity during capture:** [Fill in, for example: browsed websites in Firefox, opened Discord, visited http://neverssl.com on purpose to generate plain-HTTP traffic.]

## 2. Method

1. Captured traffic on the VM's network interface with Wireshark.
2. Ran `python3 analyze_pcap.py aa.pcapng -o my_findings.md` to get a protocol summary, top talkers, DNS activity and automated security checks.
3. Reviewed the results manually in Wireshark (Protocol Hierarchy, Conversations and display filters) to confirm what the script reported.

The script checks for: cleartext protocols (HTTP, FTP, Telnet, SMTP, POP3, IMAP), credentials sent in cleartext, SYN port scans, ARP spoofing, high ICMP volume, and unusually long DNS labels (possible tunnelling).

## 3. Protocol overview

| Protocol | Packets |
|---|---|
| UDP | 698 |
| TCP | 241 |
| DNS | 47 |
| Other | 11 |
| ICMP | 10 |
| ARP | 4 |

DNS is carried over UDP, so the 47 DNS packets are a subset of the UDP total. Most of the capture is UDP, which is typical of modern traffic such as QUIC and real-time voice or video.

_Screenshot: Wireshark Statistics > Protocol Hierarchy (`screenshots/protocol-hierarchy.png`)_

## 4. Traffic analysis

### Top talkers (by source IP)

| IP address | Packets | Notes |
|---|---|---|
| 162.159.138.232 | 491 | Largest source, mostly UDP. [Verify in Wireshark: protocol (for example QUIC) and owner. The address appears to belong to a CDN provider and the DNS lookups included Discord.] |
| 10.0.2.15 | 324 | The lab VM itself |
| 34.149.226.178 | 46 | [Verify in Wireshark] |
| 151.101.157.91 | 43 | [Verify in Wireshark] |
| 192.168.31.1 | 23 | Local gateway (DNS and ARP replies) |

### Most queried DNS names

| Domain | Queries | Notes |
|---|---|---|
| discord.gg | 12 | Discord application traffic |
| content-signature-2.cdn.mozilla.net | 11 | Firefox background security and content checks |
| discord.com | 6 | Discord |
| neverssl.com | 6 | Visited deliberately to test cleartext HTTP |
| ads.mozilla.org | 4 | Firefox |

No DNS names with unusually long labels were found, so there are no signs of DNS tunnelling.

## 5. Security findings

### Finding 1: Cleartext HTTP traffic

- **Severity:** Medium
- **Evidence:** 1 HTTP packet with data, a request to `neverssl.com` (DNS shows 6 lookups for this domain). [Add Wireshark screenshot of the `http` filter: `screenshots/http-cleartext.png`]
- **Why it matters:** HTTP sends everything unencrypted. Anyone on the same network path (public Wi-Fi, a compromised router, an attacker running ARP spoofing) can read or modify the pages and any data sent, including logins and cookies.
- **Wireshark filter used to verify:** `http`
- **Context:** This traffic was generated on purpose to test detection. No credentials were sent and the script did not flag any.
- **Recommendation:** Use HTTPS everywhere, enable the browser's HTTPS-only mode, and use a VPN on untrusted networks. Servers should redirect HTTP to HTTPS and use HSTS.

### Checks that found nothing

| Check | Result |
|---|---|
| Credentials in cleartext | None found |
| TCP SYN port scan | None detected |
| ARP spoofing (one IP with several MAC addresses) | None detected (4 ARP packets, no conflict) |
| High-volume ICMP | None (10 ICMP packets, below the threshold of 50) |
| Long DNS labels (tunnelling) | None |

This is a good result for a normal browsing session: no sign of scanning, spoofing or credential exposure.

### Observation (not a vulnerability): high-volume UDP to one host

- **Observation:** `162.159.138.232` accounts for about half of all packets (491 of 964), mostly UDP.
- **Assessment:** [After checking in Wireshark, state what it is, for example QUIC web traffic or Discord voice and video.] High volume to a single known service during active use is normal, but a defender would still check whether such flows are expected on the network.
- **Wireshark filter used to verify:** `ip.addr == 162.159.138.232`
- **Recommendation:** On a managed network, baseline normal traffic per host and alert on large unexplained flows to unfamiliar destinations.

## 6. Recommendations summary

| Priority | Action | Control type |
|---|---|---|
| 1 | Use HTTPS only; enable HTTPS-only mode in the browser; add HSTS on servers | Preventive |
| 2 | Use a VPN on untrusted networks | Preventive |
| 3 | Keep an IDS (for example Snort or Suricata) watching for scans, ARP conflicts and DNS anomalies | Detective |
| 4 | Baseline normal traffic and review large flows to unfamiliar hosts | Detective |

## 7. Limitations

- Short capture from a single machine, so it shows only that machine's view of the network.
- Most traffic is encrypted (HTTPS/QUIC), so payload contents cannot be inspected. Analysis is based on metadata such as addresses, ports and DNS names.
- The script decodes IPv4 over Ethernet only. The 11 "Other" packets were not decoded (likely IPv6 or non-IP frames).
- Detection rules are simple thresholds and indicate possible issues, not proof. They were confirmed manually in Wireshark.

## 8. Conclusion and learnings

I captured my own VM's traffic and analysed it with Wireshark and a custom Python tool. The only security concern was one deliberate plain-HTTP request, which shows how visible unencrypted traffic is to anyone who can capture it. Everything else matched normal browsing: DNS lookups, encrypted web traffic and gateway ARP replies, with no scanning, spoofing or credential leaks. [Add one sentence on what you personally learned.]

## 9. Files in this repository

| File | Purpose |
|---|---|
| `analyze_pcap.py` | Capture analyzer (Python standard library only) |
| `my_findings.md` | Analyzer output for my capture |
| `make_sample_pcap.py`, `sample_lab_traffic.pcap`, `sample_findings.md` | Synthetic sample used to test the tool (fake data, not from a real network) |
| `screenshots/` | Wireshark evidence |
