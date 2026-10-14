from collections import Counter, defaultdict
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR

WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

def parse_capture(filepath):
    proto_counts = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    conversations = Counter()
    dns_queries = Counter()
    port_hits = defaultdict(set)
    syn_counter = Counter()
    ack_counter = Counter()
    icmp_sources = Counter()
    cleartext_hits = []
    total_packets = 0
    total_volume = 0

    with PcapReader(filepath) as pcap:
        for pkt in pcap:
            total_packets += 1
            total_volume += len(pkt)

            if ARP in pkt:
                proto_counts["ARP"] += 1
                continue

            src = None
            dst = None

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst

            if not src or not dst:
                proto_counts["Other-L2"] += 1
                continue

            src_ips[src] += 1
            dst_ips[dst] += 1
            conversations[f"{src} -> {dst}"] += 1

            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags

                app_proto = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport) or "TCP-Other"
                proto_counts[app_proto] += 1

                port_hits[src].add(dport)

                if flags == "S":
                    syn_counter[src] += 1
                elif "A" in str(flags):
                    ack_counter[src] += 1

                if dport in (21, 23, 80, 110, 143):
                    pair = f"{src} -> {dst}:{dport} ({WELL_KNOWN_PORTS[dport]})"
                    if pair not in cleartext_hits:
                        cleartext_hits.append(pair)

            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

                if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                    proto_counts["DNS"] += 1
                    raw_qname = pkt[DNSQR].qname
                    try:
                        qname = raw_qname.decode("utf-8", errors="ignore").rstrip(".")
                    except Exception:
                        qname = str(raw_qname)
                    if qname:
                        dns_queries[qname] += 1
                else:
                    app_proto = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport) or "UDP-Other"
                    proto_counts[app_proto] += 1

            elif ICMP in pkt:
                proto_counts["ICMP"] += 1
                icmp_sources[src] += 1
            else:
                proto_counts["Other-IP"] += 1

    return {
        "total_packets": total_packets,
        "total_volume": total_volume,
        "protocols": proto_counts,
        "src_ips": src_ips,
        "dst_ips": dst_ips,
        "conversations": conversations,
        "dns_queries": dns_queries,
        "port_hits": port_hits,
        "syn_counter": syn_counter,
        "ack_counter": ack_counter,
        "icmp_sources": icmp_sources,
        "cleartext_hits": cleartext_hits
    }
