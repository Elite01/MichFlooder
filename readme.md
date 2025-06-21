# MichFlooder v1.0

**Author:** MichelCohen  
**License:** MIT  
**Description:** Multi-threaded packet flooder using Scapy, supporting ICMP, TCP, UDP, DNS, HTTP, and HTTPS.

## ⚠️ Disclaimer

This tool is intended for **educational and testing purposes only**.  
**Do not use on any network without explicit permission.**

---

## 🚀 Features

- Supports ICMP, TCP SYN, UDP, DNS, HTTP, and HTTPS protocols.
- Custom domain querying for DNS/HTTP(S).
- Randomized IPs, ports, and payloads.
- Adjustable packet size, interval, thread count, and total packet count.
- Multi-threaded for maximum throughput.
- Statistics reporting: packet count, total data sent, time elapsed, and throughput.

---

## 🛠️ Requirements

- Python 3.7+
- [Scapy](https://scapy.net/)

Install dependencies with:

```bash
pip install scapy
