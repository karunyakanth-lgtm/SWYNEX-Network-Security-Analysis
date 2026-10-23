# SWYNEX-Network-Security-Analysis

Task 2 of the SWYNEX Technologies internship: a **defensive** analysis of network traffic captured in a controlled lab environment.

## What this repo contains

| File | Purpose |
|---|---|
| `analyze_pcap.py` | Python (standard library only) analyzer for `.pcap` / `.pcapng` files. Summarises protocols and top talkers, and flags common security concerns. |
| `make_sample_pcap.py` | Generates a small **synthetic** capture so the analyzer can be tested with no real network data. |
| `sample_lab_traffic.pcap` | Output of the generator (39 fake packets on private lab addresses). |
| `sample_findings.md` | Analyzer output for the synthetic capture. |
| `REPORT.md` | Defensive analysis report (fill in with your own Wireshark capture). |

## Scope and ethics

Only analyse traffic you generated yourself in your own lab (for example two VMs on a host-only network) or an approved sample capture. The sample capture here is synthetic: it was written by a script and never captured from a real network.

## How to use

1. Capture lab traffic in Wireshark and save it as `.pcap` or `.pcapng` (Ethernet capture).
2. Run the analyzer (no packages to install):

   ```bash
   python analyze_pcap.py my_capture.pcapng -o my_findings.md
   ```

3. Open the same capture in Wireshark to confirm each finding (see the verification filters in `REPORT.md`), then complete `REPORT.md`.

To try the tool first:

```bash
python make_sample_pcap.py
python analyze_pcap.py sample_lab_traffic.pcap
```

## What the analyzer checks

| Check | How it works | Default threshold |
|---|---|---|
| Cleartext protocols | TCP segments with data on ports 21, 23, 25, 80, 110, 143 | any |
| Credentials in cleartext | Patterns such as `password=`, `USER`, `PASS`, `Authorization: Basic` in TCP payloads | any |
| Port scan | One source sending SYN (no ACK) to many distinct ports | 15 ports |
| ARP spoofing | One IP address claimed by more than one MAC in ARP replies | 2 MACs |
| ICMP volume | Packets per source | 50 |
| DNS tunnelling | DNS label longer than 40 characters | 40 chars |

## Limitations

- IPv4 over Ethernet only; IPv6, VLAN-tagged and Wi-Fi captures are not decoded.
- Findings are indicators, not proof. Always confirm in Wireshark and consider benign explanations (for example a vulnerability scanner you ran yourself).
- Thresholds are simple defaults and may need tuning for your lab.

## Hashtags / context

Completed as part of the SWYNEX Technologies internship, Task 2. #SWYNEX #Internship
