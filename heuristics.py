import math

def calc_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def find_weird_traffic(data):
    alerts = []

    for src, ports in data["port_hits"].items():
        if len(ports) >= 20:
            alerts.append({
                "type": "Port Scan Suspected",
                "severity": "HIGH",
                "source": src,
                "detail": f"Touched {len(ports)} unique destination TCP ports"
            })

    for src, syn_count in data["syn_counter"].items():
        ack_count = data["ack_counter"].get(src, 0)
        if syn_count >= 50 and syn_count > (ack_count * 3):
            alerts.append({
                "type": "SYN Flood / Half-Open Sweep",
                "severity": "HIGH",
                "source": src,
                "detail": f"Sent {syn_count} SYN packets vs only {ack_count} ACKs"
            })

    for domain, count in data["dns_queries"].items():
        sub = domain.split(".")[0] if "." in domain else domain
        entropy = calc_entropy(sub)
        if len(domain) > 52 or (len(sub) > 24 and entropy > 3.8):
            alerts.append({
                "type": "Suspicious DNS Query (Possible Tunneling/DGA)",
                "severity": "MEDIUM",
                "source": domain,
                "detail": f"Length={len(domain)}, Subdomain Entropy={entropy:.2f}, Count={count}"
            })

    for src, icmp_cnt in data["icmp_sources"].items():
        if icmp_cnt >= 40:
            alerts.append({
                "type": "Heavy ICMP Traffic",
                "severity": "LOW",
                "source": src,
                "detail": f"Generated {icmp_cnt} ICMP packets"
            })

    for flow in data["cleartext_hits"][:10]:
        alerts.append({
            "type": "Unencrypted Protocol Usage",
            "severity": "LOW",
            "source": flow,
            "detail": "Traffic observed over legacy cleartext port"
        })

    return alerts
