from __future__ import annotations

import ipaddress
import re
from collections import Counter
from pathlib import Path
from typing import Any


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def empty_pcap_features(path: Path | None = None) -> dict[str, Any]:
    return {
        "packet_count": 0,
        "pcap_bytes": path.stat().st_size if path and path.exists() else 0,
        "src_ip_count": 0,
        "dst_ip_count": 0,
        "dst_ports": [],
        "tcp_flow_count": 0,
        "udp_flow_count": 0,
        "external_ip_count": 0,
        "http_method_count": {},
        "http_post_count": 0,
        "dns_query_count": 0,
        "top_dst_ips": [],
        "top_dst_ports": [],
        "http_hosts": [],
        "http_paths": [],
        "user_agents": [],
        "pcap_parse_error": False,
    }


def extract_pcap_features(path: Path | None, config: dict[str, Any] | None = None) -> tuple[dict[str, Any], list[str]]:
    if path is None:
        return empty_pcap_features(None), ["missing network.pcap"]
    features = empty_pcap_features(path)
    warnings: list[str] = []
    if not path.exists():
        return features, [f"network.pcap not found: {path}"]
    if path.stat().st_size == 0:
        warnings.append("network.pcap is empty")
        return features, warnings

    try:
        return _extract_with_scapy(path, config or {})
    except ImportError:
        pass
    except Exception as exc:
        features["pcap_parse_error"] = True
        warnings.append(f"scapy pcap parse failed: {exc}")
        return features, warnings

    try:
        return _extract_with_dpkt(path, config or {})
    except ImportError:
        warnings.append("pcap parser unavailable: install scapy or dpkt for packet-level features")
        return features, warnings
    except Exception as exc:
        features["pcap_parse_error"] = True
        warnings.append(f"dpkt pcap parse failed: {exc}")
        return features, warnings


def _extract_with_scapy(path: Path, config: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    from scapy.all import DNSQR, IP, TCP, UDP, PcapReader, Raw  # type: ignore

    max_packets = int(config.get("max_packets", 50000))
    counters = _Counters(path)
    with PcapReader(str(path)) as reader:
        for index, packet in enumerate(reader):
            if index >= max_packets:
                counters.warnings.append(f"pcap truncated at max_packets={max_packets}")
                break
            counters.packet_count += 1
            if IP not in packet:
                continue
            ip = packet[IP]
            src = str(ip.src)
            dst = str(ip.dst)
            counters.src_ips[src] += 1
            counters.dst_ips[dst] += 1
            if is_external_ip(dst):
                counters.external_ips.add(dst)
            if TCP in packet:
                dport = int(packet[TCP].dport)
                counters.dst_ports[dport] += 1
                counters.tcp_flows.add((src, dst, int(packet[TCP].sport), dport))
            elif UDP in packet:
                dport = int(packet[UDP].dport)
                counters.dst_ports[dport] += 1
                counters.udp_flows.add((src, dst, int(packet[UDP].sport), dport))
            if DNSQR in packet:
                counters.dns_queries += 1
            if Raw in packet:
                counters.add_http_payload(bytes(packet[Raw].load))
    return counters.to_features(), counters.warnings


def _extract_with_dpkt(path: Path, config: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    import socket

    import dpkt  # type: ignore

    max_packets = int(config.get("max_packets", 50000))
    counters = _Counters(path)
    with path.open("rb") as handle:
        reader = dpkt.pcap.Reader(handle)
        for index, (_timestamp, buf) in enumerate(reader):
            if index >= max_packets:
                counters.warnings.append(f"pcap truncated at max_packets={max_packets}")
                break
            counters.packet_count += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
            except Exception:
                continue
            if not hasattr(ip, "src") or not hasattr(ip, "dst"):
                continue
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            counters.src_ips[src] += 1
            counters.dst_ips[dst] += 1
            if is_external_ip(dst):
                counters.external_ips.add(dst)
            transport = getattr(ip, "data", None)
            sport = getattr(transport, "sport", None)
            dport = getattr(transport, "dport", None)
            if dport is not None:
                counters.dst_ports[int(dport)] += 1
            if isinstance(transport, dpkt.tcp.TCP):
                counters.tcp_flows.add((src, dst, int(sport or 0), int(dport or 0)))
                counters.add_http_payload(bytes(transport.data or b""))
            elif isinstance(transport, dpkt.udp.UDP):
                counters.udp_flows.add((src, dst, int(sport or 0), int(dport or 0)))
                if int(dport or 0) == 53 or int(sport or 0) == 53:
                    counters.dns_queries += 1
    return counters.to_features(), counters.warnings


class _Counters:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.packet_count = 0
        self.src_ips: Counter[str] = Counter()
        self.dst_ips: Counter[str] = Counter()
        self.dst_ports: Counter[int] = Counter()
        self.tcp_flows: set[tuple[str, str, int, int]] = set()
        self.udp_flows: set[tuple[str, str, int, int]] = set()
        self.external_ips: set[str] = set()
        self.http_methods: Counter[str] = Counter()
        self.http_post_count = 0
        self.dns_queries = 0
        self.http_hosts: Counter[str] = Counter()
        self.http_paths: Counter[str] = Counter()
        self.user_agents: Counter[str] = Counter()
        self.warnings: list[str] = []

    def add_http_payload(self, payload: bytes) -> None:
        if not payload:
            return
        text = payload[:4096].decode("latin-1", errors="ignore")
        first_line = text.splitlines()[0] if text.splitlines() else ""
        parts = first_line.split()
        if not parts or parts[0].upper() not in HTTP_METHODS:
            return
        method = parts[0].upper()
        self.http_methods[method] += 1
        if method == "POST":
            self.http_post_count += 1
        if len(parts) > 1:
            self.http_paths[parts[1][:200]] += 1
        host_match = re.search(r"(?im)^Host:\s*([^\r\n]+)", text)
        if host_match:
            self.http_hosts[host_match.group(1).strip()[:200]] += 1
        ua_match = re.search(r"(?im)^User-Agent:\s*([^\r\n]+)", text)
        if ua_match:
            self.user_agents[ua_match.group(1).strip()[:200]] += 1

    def to_features(self) -> dict[str, Any]:
        return {
            "packet_count": self.packet_count,
            "pcap_bytes": self.path.stat().st_size if self.path.exists() else 0,
            "src_ip_count": len(self.src_ips),
            "dst_ip_count": len(self.dst_ips),
            "dst_ports": sorted(self.dst_ports.keys()),
            "tcp_flow_count": len(self.tcp_flows),
            "udp_flow_count": len(self.udp_flows),
            "external_ip_count": len(self.external_ips),
            "http_method_count": dict(self.http_methods),
            "http_post_count": self.http_post_count,
            "dns_query_count": self.dns_queries,
            "top_dst_ips": self.dst_ips.most_common(10),
            "top_dst_ports": self.dst_ports.most_common(10),
            "http_hosts": self.http_hosts.most_common(10),
            "http_paths": self.http_paths.most_common(10),
            "user_agents": self.user_agents.most_common(10),
            "pcap_parse_error": False,
        }


def is_external_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )

