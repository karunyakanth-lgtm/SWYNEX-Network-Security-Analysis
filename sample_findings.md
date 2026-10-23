# Findings for `sample_lab_traffic.pcap`

Total packets: **39**

## Protocol distribution

| Protocol | Packets |
|---|---|
| TCP | 33 |
| UDP | 4 |
| DNS | 4 |
| ARP | 2 |

## Top talkers (source IP)

| IP | Packets |
|---|---|
| 192.168.56.66 | 30 |
| 192.168.56.10 | 7 |

## Most queried DNS names

| Name | Queries |
|---|---|
| example.test | 2 |
| lab.example.test | 1 |
| a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6.tunnel.example.test | 1 |

## Security observations

| Severity | Observation | Recommended action |
|---|---|---|
| High | Possible credentials in cleartext: 192.168.56.10 -> 192.168.56.20:21 | Rotate the affected credentials and enforce TLS. |
| High | Possible credentials in cleartext: 192.168.56.10 -> 192.168.56.20:80 | Rotate the affected credentials and enforce TLS. |
| High | Possible port scan from 192.168.56.66 (30 distinct ports probed) | Confirm the source is authorised; rate-limit or block at the firewall; review IDS alerts. |
| High | ARP anomaly: 192.168.56.1 claimed by 2 MAC addresses ['aa:aa:aa:00:00:66', 'aa:aa:aa:00:00:fe'] | Possible ARP spoofing. Enable Dynamic ARP Inspection or static ARP for critical hosts. |
| Medium | Cleartext HTTP traffic (1 packets) | Replace with an encrypted equivalent (HTTPS, SFTP, SSH, TLS-enabled mail). |
| Medium | Cleartext FTP traffic (2 packets) | Replace with an encrypted equivalent (HTTPS, SFTP, SSH, TLS-enabled mail). |
| Medium | Unusually long DNS label: a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6.tunnel. | Possible DNS tunnelling or DGA; inspect the domain and the querying host. |
