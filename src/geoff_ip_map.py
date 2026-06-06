"""Geoff DFIR — IP connection extractor for the interactive IP map feature."""
import json
import re
from collections import defaultdict
from pathlib import Path


_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.")
_PRIVATE_RANGES_172 = range(16, 32)


def _normalize_ip(ip_str):
    """Strip leading zeros from zero-padded IPs (e.g. tcpflow '069.022.167.214')."""
    try:
        parts = str(ip_str).strip().split(".")
        if len(parts) == 4:
            return ".".join(str(int(p)) for p in parts)
    except (ValueError, AttributeError):
        pass
    return str(ip_str).strip() if ip_str else ""


def _is_valid_ip(ip):
    """Basic IPv4 validity check."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _classify_ip(ip):
    """Return 'internal' for RFC 1918/loopback/link-local, else 'external'."""
    for prefix in _PRIVATE_PREFIXES:
        if ip.startswith(prefix):
            return "internal"
    if ip.startswith("172."):
        try:
            if int(ip.split(".")[1]) in _PRIVATE_RANGES_172:
                return "internal"
        except (ValueError, IndexError):
            pass
    return "external"


class IPConnectionExtractor:
    """Extracts IP-to-host relationships from existing case findings."""

    def __init__(self, case_path):
        self.case_path = Path(case_path)
        self._nodes = {}   # ip -> {group, hostname, findings, connections}
        self._edges = defaultdict(lambda: {"count": 0, "findings": []})
        self._ip_to_hostname = {}

    def _ensure_node(self, ip, finding_ref=None):
        if not _is_valid_ip(ip):
            return
        if ip not in self._nodes:
            self._nodes[ip] = {
                "group": _classify_ip(ip),
                "hostname": None,
                "findings": [],
                "connections": set(),
            }
        if finding_ref:
            self._nodes[ip]["findings"].append(finding_ref)

    def _add_edge(self, src, dst, protocol="TCP", port=None, finding_ref=None):
        src = _normalize_ip(src)
        dst = _normalize_ip(dst)
        if not _is_valid_ip(src) or not _is_valid_ip(dst) or src == dst:
            return
        self._ensure_node(src, finding_ref)
        self._ensure_node(dst, finding_ref)
        self._nodes[src]["connections"].add(dst)
        self._nodes[dst]["connections"].add(src)
        key = (src, dst, protocol, port)
        self._edges[key]["count"] += 1
        if finding_ref:
            self._edges[key]["findings"].append(finding_ref)

    def _process_finding(self, d, ref):
        fn = d.get("function", "")
        result = d.get("result") or {}
        if not isinstance(result, dict):
            result = {}
        ev_chain = d.get("evidence_chain") or {}
        if not isinstance(ev_chain, dict):
            ev_chain = {}

        if fn == "extract_flows":
            for flow in (result.get("flows") or []):
                if not isinstance(flow, dict):
                    continue
                src = _normalize_ip(flow.get("src_ip", ""))
                dst = _normalize_ip(flow.get("dst_ip", ""))
                port = flow.get("dst_port") or flow.get("src_port")
                self._add_edge(src, dst, "TCP", port, ref)

        elif fn == "analyze_pcap":
            for conv in (result.get("conversations") or []):
                if not isinstance(conv, dict):
                    continue
                a = _normalize_ip(conv.get("address_a", ""))
                b = _normalize_ip(conv.get("address_b", ""))
                if _is_valid_ip(a) and _is_valid_ip(b):
                    self._add_edge(a, b, "TCP", None, ref)
            for ip in (result.get("unique_ips") or []):
                ip_n = _normalize_ip(ip)
                if _is_valid_ip(ip_n):
                    self._ensure_node(ip_n, ref)
            for dns in (result.get("dns_queries") or []):
                if not isinstance(dns, dict):
                    continue
                query = dns.get("query", "")
                answer = _normalize_ip(dns.get("answer", ""))
                if query and _is_valid_ip(answer):
                    self._ip_to_hostname[answer] = query

        elif fn == "extract_http":
            for req in (result.get("http_requests") or []):
                if not isinstance(req, dict):
                    continue
                host = req.get("host", "")
                # Associate domain host with any IP already known for it
                if host and not _is_valid_ip(host):
                    for ip, hn in self._ip_to_hostname.items():
                        if hn == host and ip in self._nodes:
                            self._nodes[ip]["hostname"] = host

        # Generic: scan result + evidence_chain for explicit IP fields
        for obj in (result, ev_chain):
            if not isinstance(obj, dict):
                continue
            src = _normalize_ip(obj.get("source_ip", "") or obj.get("local_address", ""))
            dst = _normalize_ip(obj.get("destination_ip", "") or obj.get("remote_address", ""))
            if _is_valid_ip(src) and _is_valid_ip(dst):
                self._add_edge(src, dst, "TCP", None, ref)
            elif _is_valid_ip(src):
                self._ensure_node(src, ref)
            elif _is_valid_ip(dst):
                self._ensure_node(dst, ref)
            for field in ("ip_address",):
                val = _normalize_ip(obj.get(field, ""))
                if _is_valid_ip(val):
                    self._ensure_node(val, ref)

    def _read_findings_jsonl(self):
        findings_file = self.case_path / "findings.jsonl"
        if not findings_file.exists():
            return
        with open(findings_file, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._process_finding(d, "findings.jsonl:%d" % lineno)

    def _read_report_json(self):
        """Scan find_evil_report.json indicator_hits for IP addresses."""
        report_file = self.case_path / "reports" / "find_evil_report.json"
        if not report_file.exists():
            return
        try:
            data = json.loads(report_file.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        indicator_hits = data.get("indicator_hits") or []
        if isinstance(indicator_hits, list):
            for hit in indicator_hits:
                for ip in ip_pattern.findall(json.dumps(hit) if isinstance(hit, dict) else str(hit)):
                    ip_n = _normalize_ip(ip)
                    if _is_valid_ip(ip_n):
                        self._ensure_node(ip_n, "indicator_hits")

    def extract(self):
        """Run extraction and return {nodes, edges} dict."""
        self._read_findings_jsonl()
        self._read_report_json()

        for ip, hostname in self._ip_to_hostname.items():
            if ip in self._nodes and not self._nodes[ip]["hostname"]:
                self._nodes[ip]["hostname"] = hostname

        nodes = []
        for ip, info in self._nodes.items():
            nodes.append({
                "id": ip,
                "label": info["hostname"] if info["hostname"] else ip,
                "group": info["group"],
                "hostname": info["hostname"],
                "connections": len(info["connections"]),
                "findings_count": len(set(info["findings"])),
            })

        edges = []
        seen = set()
        for (src, dst, protocol, port), info in self._edges.items():
            key = tuple(sorted([src, dst])) + (protocol, port)
            if key in seen:
                continue
            seen.add(key)
            edges.append({
                "source": src,
                "target": dst,
                "protocol": protocol,
                "port": port,
                "findings_count": len(info["findings"]),
            })

        return {"nodes": nodes, "edges": edges}
