# Findings: `aa.pcapng` — working notes

**Status: needs final Wireshark verification before submission.** These notes describe a personal Kali Linux VirtualBox NAT capture. The notes report 964 packets and VM address `10.0.2.15`. Do not treat draft counts or interpretations as final until checked against the original capture.

## Draft summary

| # | Observation | Draft status |
|---|---|---|
| 1 | TCP data on port 80 | Possible cleartext HTTP indicator; confirm application payload |
| 2 | Failed connection attempt to `neverssl.com` | Informational; verify packet sequence and endpoint tuple |
| 3 | IPv6 traffic not decoded by analyzer | Reported in notes; confirm protocol hierarchy |
| 4 | Duplicate DNS response and ICMP port unreachable | Reported in notes; confirm packet details |
| 5 | Large UDP flow to `162.159.138.232` | Reported in notes; do not infer application without protocol evidence |

No port scan, ARP conflict, credential-like text, high ICMP volume or long DNS label was reported by the current analyzer run. Re-run the analyzer against the original capture before submission and compare its output with these notes.

## Observation 1: TCP data on port 80

- **Potential severity:** Medium only if valid unencrypted HTTP is confirmed.
- **Draft evidence:** Analyzer reportedly counted one TCP packet carrying data on port 80.
- **Verify:** In Wireshark, try `tcp.port == 80 && tcp.len > 0` and then `http`. Inspect packet details and Follow TCP Stream. Record the packet number, source/destination tuple and request line or response status only if visible.
- **Risk:** Confirmed HTTP content is unencrypted. Do not claim credentials, cookies or personal information were exposed unless the packet actually shows that.
- **Recommendation:** Prefer HTTPS; configure redirects and HSTS on servers where appropriate.

**Unresolved discrepancy:** The notes below say the connection to `neverssl.com` did not send an HTTP request, but the port-80 data indicator has not been tied to a specific stream. Check the packet number and TCP stream. They may be separate flows; do not attribute one to the other without evidence.

## Observation 2: Failed connection attempt

- **Draft evidence:** Notes say DNS resolved `neverssl.com` to `34.223.124.45`, TCP SYN retransmissions occurred, and a reset was later seen.
- **Verify with filters:** `ip.addr == 34.223.124.45` and `tcp.analysis.retransmission`. Confirm the exact packet numbers and whether the final reset belongs to the same connection.
- **Interpretation:** A failed connection can be caused by service availability, filtering or network conditions. By itself, it is not evidence of an attack.

## Observation 3: IPv6 traffic

The previous notes report 11 packets that the IPv4-focused analyzer categorised as “Other”. [VERIFY in Wireshark that these are IPv6/ICMPv6 packets and update the count if needed.] IPv6 is outside the analyzer's current decoded path, so these packets should not be interpreted as malicious just because the script did not decode them.

## Observation 4: DNS and ICMP

The previous notes report a duplicate AAAA response for `neverssl.com` and an ICMP destination-unreachable/port-unreachable packet. [VERIFY packet numbers, DNS transaction ID, query/response matching and ICMP details.] Duplicate responses can have benign causes; do not label them spoofing without stronger evidence.

## Observation 5: Large UDP flow

- **Draft evidence:** Notes report 491 of 964 packets involving `162.159.138.232`, mostly UDP.
- **Verify:** Use `ip.addr == 162.159.138.232`; inspect UDP ports, packet direction, decoded protocol and stream context.
- **Do not assume:** DNS lookups for `discord.gg` or `discord.com` do not by themselves prove this flow is Discord voice/video or QUIC.
- **Recommendation:** Baseline expected traffic and investigate large unexplained flows in context.

## Checks reported as not triggering

| Check | Draft result | Meaning |
|---|---|---|
| Credential-like patterns | None reported | Does not prove no credentials were sent |
| TCP SYN scan (15+ distinct ports) | None reported | Only this simple threshold was checked |
| ARP IP/MAC conflict | None reported | Only conflicts visible to this capture and rule |
| ICMP volume (50+ packets/source) | None reported | Does not rule out other ICMP patterns |
| DNS label longer than 40 characters | None reported | Does not rule out all DNS tunnelling |

## Method

1. Capture your own lab traffic or use an approved sample.
2. Run `python3 analyze_pcap.py aa.pcapng -o my_findings.md`.
3. Verify each indicator in Wireshark.
4. Save only screenshots that contain relevant, readable evidence and no private information.
5. Update `REPORT.md` with the confirmed packet details and your own learning.

## Limitations

- Single host and short capture.
- Encrypted traffic limits payload inspection.
- Analyzer primarily decodes IPv4 over Ethernet.
- Heuristics can miss threats and produce false positives; results are indicators, not proof.
