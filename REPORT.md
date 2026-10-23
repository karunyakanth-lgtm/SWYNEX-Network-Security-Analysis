# Defensive Network Traffic Analysis Report

**Author:** [Your name]  
**Date:** 23 October 2026  
**Internship task:** SWYNEX Technologies — Task 2: Network Security Analysis

> **Submission check:** This report contains preliminary notes from the lab capture. Complete every item marked `[VERIFY]` against your actual capture before submitting. Do not invent packet evidence or describe an unverified indicator as a confirmed finding.

## 1. Scope and environment

- **Capture source:** Personal Kali Linux VM in VirtualBox using NAT, as recorded in the lab notes.
- **VM address:** `10.0.2.15`, according to the notes.
- **Tools:** Wireshark and the repository's Python analyzer.
- **Capture:** `aa.pcapng`, reported in the notes as 964 packets.
- **Activity during capture:** [VERIFY: list the browsing or applications you actually used.]

Keep the raw capture local unless you have reviewed it for private data and intentionally decided it is safe to publish.

## 2. Method

1. Captured traffic visible to the lab VM in Wireshark.
2. Ran `python3 analyze_pcap.py aa.pcapng -o my_findings.md`.
3. Used Wireshark display filters and packet details to check the analyzer's indicators.
4. Recorded both possible findings and checks that did not trigger.

The analyzer uses heuristics. A match is a lead to investigate, not proof of an attack or data exposure.

## 3. Protocol overview

The current notes contain these counts. **[VERIFY]** Recalculate them from the original capture and compare them with the analyzer output before submission.

| Protocol | Packets in draft notes |
|---|---:|
| UDP | 698 |
| TCP | 241 |
| DNS | 47 |
| Other | 11 |
| ICMP | 10 |
| ARP | 4 |

DNS traffic carried over UDP is a subset of UDP traffic, so do not add DNS to UDP as though the categories were mutually exclusive.

**Screenshot:** The repository contains several timestamp-named screenshots and `screenshots/swynex-task2-findings.png`. [VERIFY which image shows Protocol Hierarchy; use its actual filename and ensure it contains readable evidence.]

## 4. Traffic analysis

The following figures are carried over from the working notes and must be checked against the capture before they are presented as final results.

| IP address | Packets in draft notes | Required verification |
|---|---:|---|
| `162.159.138.232` | 491 | Inspect ports, protocol and packet direction; do not infer the application from DNS names alone |
| `10.0.2.15` | 324 | Confirm source-host count |
| `34.149.226.178` | 46 | Confirm source-host count and context |
| `151.101.157.91` | 43 | Confirm source-host count and context |
| `192.168.31.1` | 23 | Confirm this address is the gateway in this capture |

The working notes list DNS queries for names including `discord.gg`, `content-signature-2.cdn.mozilla.net`, `discord.com`, `neverssl.com`, and `ads.mozilla.org`. [VERIFY query counts and whether each name is relevant to your own activity.]

## 5. Security observations

### Observation A: TCP data on port 80

- **Draft status:** Possible cleartext HTTP indicator; not yet established as a confirmed HTTP request.
- **Evidence in notes:** The analyzer reportedly counted one TCP segment carrying data on port 80.
- **Verify in Wireshark:** Use `tcp.port == 80 && tcp.len > 0`, then inspect the packet details and TCP stream. Use `http` to check whether Wireshark decodes a valid HTTP request or response.
- **Record only after verification:** packet number, source/destination IP and ports, request line or response status if visible, and the screenshot filename.
- **Risk if confirmed:** HTTP content is not encrypted and may be readable or modifiable by someone on the network path. Do not claim credentials, cookies or personal data were exposed unless the packet actually shows that.
- **Recommendation:** Prefer HTTPS and configure HTTPS redirects and HSTS on servers where appropriate.

**Important:** The original notes say the connection to `neverssl.com` failed before any HTTP request was sent. That does not automatically explain the separate port-80 data indicator. Inspect the packet number, TCP stream and endpoint tuple to determine whether they are different flows. Do not attribute the port-80 packet to `neverssl.com` unless the capture proves it.

### Observation B: Failed connection attempt

- **Draft status:** Informational; verify packet numbers and sequence before submission.
- **Working notes:** DNS reportedly resolved `neverssl.com` to `34.223.124.45`; SYN retransmissions were followed by a reset, and the notes say no HTTP request was sent.
- **Wireshark filters:** `ip.addr == 34.223.124.45` and `tcp.analysis.retransmission`.
- **Interpretation:** A failed connection can be caused by filtering, service availability or network conditions; it is not evidence of an attack by itself.

### Observation C: Large UDP flow

- **Draft status:** Needs protocol verification.
- **Working notes:** `162.159.138.232` accounted for 491 of 964 packets, mostly UDP.
- **Wireshark filter:** `ip.addr == 162.159.138.232`.
- **[VERIFY]** Check UDP ports and packet details before describing this as QUIC, Discord voice/video or another specific application. A high packet count alone is not a vulnerability.
- **Recommendation:** On a managed network, baseline expected traffic and investigate large unexplained flows.

### Checks reported as not triggering

The notes report no matches for these checks. Confirm the latest analyzer output before presenting them as final.

| Check | Preliminary result |
|---|---|
| Credential-like text patterns | No matches reported |
| TCP SYN scan (15 or more distinct ports) | None reported |
| ARP address/MAC conflict | None reported |
| High ICMP volume (50 or more packets from one source) | None reported |
| DNS label longer than 40 characters | None reported |

A heuristic that did not trigger does not prove the network is free of threats.

## 6. Recommendations

1. Prefer encrypted protocols and verify HTTP traffic before describing exposure.
2. Investigate failed connections using packet sequences and endpoint tuples.
3. Establish a baseline before treating a large flow as suspicious.
4. Treat analyzer results as leads and manually verify them in Wireshark.
5. Improve parser validation and protocol coverage before relying on the tool operationally.

## 7. Limitations

- Short capture from one VM; only traffic visible at that capture point is represented.
- Encrypted traffic limits payload inspection.
- The custom analyzer focuses on IPv4 over Ethernet and does not fully decode IPv6 or all link-layer formats.
- Detection rules are simple heuristics and can miss threats or produce false positives.
- Some counts and interpretations above are copied from working notes and still require verification.

## 8. Conclusion and learning

[VERIFY: write a conclusion that matches the final packet evidence after resolving the port-80 / `neverssl.com` discrepancy.]  
[Add one honest sentence about what you personally learned from using Wireshark and the Python analyzer.]

## 9. Repository files

- `analyze_pcap.py` — analyzer
- `FINDINGS.md` — working notes and outstanding verification items
- `make_sample_pcap.py`, `sample_lab_traffic.pcap`, `sample_findings.md` — synthetic test data and sample output
- `tests/test_analyze_pcap.py` — regression tests
- `screenshots/` — screenshots; confirm each screenshot's purpose before referencing it
