#!/usr/bin/env python3
"""Geoff DFIR - PB-SIFT-063 Chat & Messaging Aggregation.

Reads findings from:
  - PB-SIFT-021 (Mobile Forensics) — SMS, WhatsApp, Telegram, call logs
  - PB-SIFT-031 (Enterprise Collaboration) — Teams, Slack, Discord
  - PB-SIFT-060 (Communications) — email messages already structured

Produces:
  - Normalized unified message list
  - Cross-platform communication graph
  - Identity resolution (same person across platforms)
  - Unified communications timeline
  - LLM narrative
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Platform detection patterns
# ---------------------------------------------------------------------------

_MOBILE_PLATFORM_PATTERNS = {
    "sms": [r"\bsms\b", r"text.?message", r"short.?message"],
    "whatsapp": [r"whatsapp", r"wa_db", r"msgstore"],
    "telegram": [r"telegram", r"tg_msg", r"telegramdesktop"],
    "imessage": [r"imessage", r"sms\.db", r"chat\.db", r"isms"],
    "signal": [r"signal", r"signal\.db", r"sqlcipher.*signal"],
    "call_log": [r"call.?log", r"incoming.?call", r"outgoing.?call", r"missed.?call"],
}

_COLLAB_PLATFORM_PATTERNS = {
    "teams": [r"microsoft.?teams", r"msteams", r"teams\.sqlite", r"teams.*message"],
    "slack": [r"\bslack\b", r"slack.*workspace", r"slack.*channel", r"slack.*message"],
    "discord": [r"\bdiscord\b", r"discord.*message", r"discord.*channel", r"discord.*guild"],
}

# Unified chat message parsing regexes
_SENDER_RE = re.compile(r"(?:^|\n)\s*(?:sender|from|author|user)\s*[:\-]\s*(.+?)(?=\n|$)", re.IGNORECASE)
_RECIPIENT_RE = re.compile(r"(?:^|\n)\s*(?:recipient|to|receiver)\s*[:\-]\s*(.+?)(?=\n|$)", re.IGNORECASE)
_MESSAGE_RE = re.compile(r"(?:^|\n)\s*(?:message|body|content|text)\s*[:\-]\s*(.+?)(?=\n|$)", re.IGNORECASE)
_TIMESTAMP_RE = re.compile(r"(?:^|\n)\s*(?:timestamp|date|time|sent_at|received_at)\s*[:\-]\s*(.+?)(?=\n|$)", re.IGNORECASE)

# Phone number normalizer
_PHONE_RE = re.compile(r"\+?[\d\s\-\(\)]{7,20}")
# Email address
_EMAIL_RE = re.compile(r"[\w.+\-]+@[\w.\-]+\.\w+")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_platform(output: str, function: str, module: str) -> Optional[str]:
    """Return the most likely platform for a finding record."""
    text = f"{output} {function} {module}".lower()
    for platform, patterns in {**_MOBILE_PLATFORM_PATTERNS, **_COLLAB_PLATFORM_PATTERNS}.items():
        for p in patterns:
            if re.search(p, text):
                return platform
    return None


def _normalize_identity(raw: str) -> str:
    """Normalize an identifier to a canonical form."""
    raw = raw.strip()
    # Prefer email address
    em = _EMAIL_RE.search(raw)
    if em:
        return em.group(0).lower()
    # Phone number
    ph = _PHONE_RE.search(raw)
    if ph:
        return re.sub(r"[\s\-\(\)]", "", ph.group(0))
    return raw.lower()[:120]


def _parse_chat_block(text: str, platform: str) -> Optional[dict]:
    """Parse sender/recipient/message/timestamp from a chat block."""
    sm = _SENDER_RE.search(text)
    rm = _RECIPIENT_RE.search(text)
    mm = _MESSAGE_RE.search(text)
    tm = _TIMESTAMP_RE.search(text)
    if not sm and not rm:
        return None
    return {
        "from": _normalize_identity(sm.group(1)) if sm else "",
        "to": [_normalize_identity(r.strip()) for r in (rm.group(1).split(",") if rm else [])],
        "body": mm.group(1).strip()[:500] if mm else "",
        "timestamp": tm.group(1).strip()[:50] if tm else "",
        "platform": platform,
    }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ChatAggregator:
    """PB-SIFT-063 — Chat & Messaging Aggregation."""

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_findings(self, findings: list) -> list:
        """Extract normalized chat messages from all relevant findings."""
        messages = []
        seen: set = set()

        for rec in findings:
            module = str(rec.get("module", "")).lower()
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            playbook = str(rec.get("playbook", ""))

            # Only process mobile and collaboration findings
            is_mobile = module in ("mobile", "android", "ios") or any(
                re.search(p, f"{function} {output[:200]}".lower())
                for patterns in _MOBILE_PLATFORM_PATTERNS.values()
                for p in patterns
            )
            is_collab = module == "collaboration" or any(
                re.search(p, f"{function} {output[:200]}".lower())
                for patterns in _COLLAB_PLATFORM_PATTERNS.values()
                for p in patterns
            )

            if not is_mobile and not is_collab:
                continue

            platform = _detect_platform(output, function, module) or (
                "mobile" if is_mobile else "collaboration"
            )

            # Split output into blocks and parse each
            blocks = re.split(r"\n(?=(?:sender|from|author)\s*[:\-])", output, flags=re.IGNORECASE)
            for block in blocks:
                msg = _parse_chat_block(block, platform)
                if msg:
                    key = f"{msg['from']}|{'|'.join(msg['to'])}|{msg['body'][:50]}|{platform}"
                    if key not in seen:
                        seen.add(key)
                        msg["source_playbook"] = playbook
                        msg["source_function"] = function
                        messages.append(msg)

        return messages

    def ingest_email_messages(self, comm_result: dict) -> list:
        """Import already-structured email messages from PB-SIFT-060 output."""
        raw_msgs = comm_result.get("messages", [])
        messages = []
        for m in raw_msgs:
            messages.append({
                "from": m.get("from", ""),
                "to": m.get("to", []),
                "body": m.get("subject", ""),  # subject as message proxy
                "timestamp": m.get("date", ""),
                "platform": "email",
                "source_playbook": m.get("source_playbook", "PB-SIFT-060"),
                "source_function": m.get("source_function", ""),
            })
        return messages

    # ------------------------------------------------------------------
    # Cross-platform graph
    # ------------------------------------------------------------------

    def build_cross_platform_graph(self, messages: list) -> dict:
        """Build person→person communication graph across all platforms."""
        graph: dict = defaultdict(lambda: defaultdict(lambda: {
            "count": 0,
            "platforms": set(),
            "timestamps": [],
        }))

        for msg in messages:
            sender = msg.get("from", "")
            platform = msg.get("platform", "unknown")
            ts = msg.get("timestamp", "")
            for recipient in msg.get("to", []):
                if sender and recipient and sender != recipient:
                    edge = graph[sender][recipient]
                    edge["count"] += 1
                    edge["platforms"].add(platform)
                    if ts:
                        edge["timestamps"].append(ts)

        # Serialize (sets → lists)
        result = {}
        for person, targets in graph.items():
            result[person] = {}
            for target, data in targets.items():
                result[person][target] = {
                    "message_count": data["count"],
                    "platforms": sorted(data["platforms"]),
                    "platform_count": len(data["platforms"]),
                    "timestamps": data["timestamps"][:10],
                    "is_cross_platform": len(data["platforms"]) > 1,
                }
        return result

    # ------------------------------------------------------------------
    # Identity resolution
    # ------------------------------------------------------------------

    def resolve_identities(self, messages: list) -> list:
        """Cluster identifiers that likely belong to the same person."""
        # Map: email → set of phone numbers and vice versa found near each other
        email_to_phones: dict = defaultdict(set)
        phone_to_emails: dict = defaultdict(set)

        for msg in messages:
            identifiers = [msg.get("from", "")] + msg.get("to", [])
            emails = [i for i in identifiers if _EMAIL_RE.search(i)]
            phones = [i for i in identifiers if _PHONE_RE.search(i) and not _EMAIL_RE.search(i)]
            for e in emails:
                for p in phones:
                    email_to_phones[e].add(p)
                    phone_to_emails[p].add(e)

        clusters = []
        seen: set = set()
        for email, phones in email_to_phones.items():
            if email in seen:
                continue
            group = {email} | phones
            for p in phones:
                group |= phone_to_emails[p]
            clusters.append({
                "canonical": email,
                "aliases": sorted(group - {email}),
                "platforms": list({
                    msg.get("platform", "")
                    for msg in messages
                    if any(i in group for i in [msg.get("from", "")] + msg.get("to", []))
                }),
            })
            seen |= group

        return clusters

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def build_timeline(self, messages: list) -> list:
        """Sort messages by timestamp into a unified communications timeline."""
        timestamped = [m for m in messages if m.get("timestamp")]

        def _sort_key(m: dict) -> str:
            return m.get("timestamp", "")

        timestamped.sort(key=_sort_key)
        return timestamped[:500]  # cap for large cases

    # ------------------------------------------------------------------
    # Cross-platform pairs
    # ------------------------------------------------------------------

    def find_cross_platform_pairs(self, graph: dict) -> list:
        """Identify person pairs that communicate on multiple platforms."""
        pairs = []
        seen: set = set()
        for person_a, targets in graph.items():
            for person_b, data in targets.items():
                if data["platform_count"] < 2:
                    continue
                key = tuple(sorted([person_a, person_b]))
                if key not in seen:
                    seen.add(key)
                    pairs.append({
                        "person_a": person_a,
                        "person_b": person_b,
                        "platforms": data["platforms"],
                        "total_messages": data["message_count"],
                        "note": f"Communicates via {', '.join(data['platforms'])}",
                        "confidence": "HIGH",
                    })
        pairs.sort(key=lambda x: -x["total_messages"])
        return pairs[:50]

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def generate_report(
        self,
        messages: list,
        graph: dict,
        identities: list,
        timeline: list,
        cross_platform_pairs: list,
    ) -> dict:
        platform_counts: Counter = Counter(m.get("platform", "unknown") for m in messages)
        return {
            "playbook": "PB-SIFT-063",
            "playbook_name": "Chat & Messaging Aggregation",
            "total_messages": len(messages),
            "platform_breakdown": dict(platform_counts),
            "unique_persons": len(graph),
            "cross_platform_pairs": cross_platform_pairs,
            "resolved_identities": identities[:50],
            "communication_graph": graph,
            "unified_timeline": timeline[:200],
        }

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        case_dir: str,
        findings: list,
        comm_result: Optional[dict] = None,
        call_llm_func: Optional[Callable] = None,
    ) -> dict:
        messages = self.ingest_findings(findings)
        if comm_result:
            messages += self.ingest_email_messages(comm_result)

        graph = self.build_cross_platform_graph(messages)
        identities = self.resolve_identities(messages)
        timeline = self.build_timeline(messages)
        cross_platform_pairs = self.find_cross_platform_pairs(graph)

        report = self.generate_report(messages, graph, identities, timeline, cross_platform_pairs)

        narrative = ""
        if call_llm_func and messages:
            narrative = self._generate_narrative(report, call_llm_func)
        report["narrative"] = narrative

        if case_dir:
            out_path = Path(case_dir) / "output" / "PB-SIFT-063_chat_aggregator.json"
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(report, default=str, indent=2))
            except OSError:
                pass

        return report

    def _generate_narrative(self, report: dict, call_llm_func: Callable) -> str:
        platforms = report.get("platform_breakdown", {})
        pairs = report.get("cross_platform_pairs", [])[:5]
        identities = report.get("resolved_identities", [])[:5]
        parts = [
            "You are a digital forensics analyst. Summarize the cross-platform communications findings.",
            f"Total messages: {report['total_messages']}, platforms: {list(platforms.keys())}, unique persons: {report['unique_persons']}",
        ]
        if pairs:
            parts.append("Cross-platform communication pairs:")
            for p in pairs:
                parts.append(f"  - {p['person_a']} ↔ {p['person_b']}: {p['total_messages']} messages via {', '.join(p['platforms'])}")
        if identities:
            parts.append("Resolved identities (same person, multiple platforms):")
            for ident in identities:
                parts.append(f"  - {ident['canonical']} also known as: {', '.join(ident['aliases'][:3])}")
        parts.append(
            "\nWrite a concise forensic narrative (2-3 paragraphs) covering: "
            "(1) the range of communication platforms used, "
            "(2) key actors and their cross-platform relationships, "
            "(3) whether platform-switching suggests evasion, "
            "(4) most suspicious communication patterns."
        )
        try:
            return call_llm_func("\n".join(parts), agent_type="manager") or ""
        except Exception:
            return ""
