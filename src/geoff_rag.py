#!/usr/bin/env python3
"""Geoff DFIR - Case RAG (Retrieval-Augmented Generation) for interactive Q&A.

After a Find Evil run, this module lets analysts ask free-form questions about
the case.  It uses a simple TF-IDF-style keyword index over all case findings
(no external vector-store dependencies) and answers via the existing Geoff LLM.

Index format: case_dir/rag/rag_index.json
  {
    "chunks": [{"id": int, "text": str, "source": str, "keywords": [str]}],
    "built_at": "ISO datetime",
    "chunk_count": int,
  }
"""

import json
import math
import re
import string
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "not", "no", "and", "or",
    "but", "if", "in", "on", "at", "to", "for", "of", "with", "from",
    "by", "as", "this", "that", "it", "its", "he", "she", "they", "we",
    "i", "you", "my", "your", "his", "her", "their", "our", "what",
    "which", "who", "when", "where", "how", "why", "true", "false",
    "null", "none", "unknown", "n/a",
})

_PUNCT_RE = re.compile(r"[" + re.escape(string.punctuation) + r"\s]+")


def _tokenize(text: str) -> list:
    tokens = _PUNCT_RE.split(text.lower())
    return [t for t in tokens if len(t) > 2 and t not in _STOP_WORDS]


def _chunk_text(text: str, chunk_size: int = 400, overlap: int = 80) -> list:
    """Split text into overlapping word chunks."""
    words = text.split()
    if len(words) <= chunk_size:
        return [text]
    chunks = []
    start = 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap
    return chunks


# ---------------------------------------------------------------------------
# Record → text conversion
# ---------------------------------------------------------------------------

def _record_to_text(rec: dict) -> str:
    """Convert a findings record to a searchable text blob."""
    parts = []
    for field in ("playbook", "module", "function", "status", "description",
                  "output", "error", "evidence_chain", "device_id"):
        val = rec.get(field)
        if val and isinstance(val, str):
            parts.append(val)
        elif val and isinstance(val, dict):
            parts.append(json.dumps(val, default=str))
    return " ".join(parts)


def _findings_from_jsonl(path: Path) -> list:
    """Read findings from a JSONL file."""
    records = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    except OSError:
        pass
    return records


def _json_files_in(case_dir: Path) -> list:
    """Collect all JSON / JSONL output files in the case directory."""
    files = []
    for pattern in ("output/*.json", "reports/*.json", "findings.jsonl"):
        files.extend(case_dir.glob(pattern))
    return files


# ---------------------------------------------------------------------------
# CaseRAG
# ---------------------------------------------------------------------------

class CaseRAG:
    """Lightweight keyword-index RAG over Geoff case findings."""

    INDEX_SUBDIR = "rag"
    INDEX_FILE = "rag_index.json"
    MAX_CHUNKS = 5000

    def _index_path(self, case_dir: Path) -> Path:
        return case_dir / self.INDEX_SUBDIR / self.INDEX_FILE

    # ------------------------------------------------------------------
    # Build / load index
    # ------------------------------------------------------------------

    def index_case(self, case_dir: str) -> dict:
        """Chunk all findings into a keyword index and persist it.

        Returns the index dict.
        """
        case_path = Path(case_dir)
        chunks: list = []
        doc_freq: Counter = Counter()

        # JSONL findings
        findings_file = case_path / "findings.jsonl"
        if findings_file.exists():
            for rec in _findings_from_jsonl(findings_file):
                text = _record_to_text(rec)
                if not text.strip():
                    continue
                source = f"findings:{rec.get('playbook','?')}:{rec.get('function','?')}"
                for chunk in _chunk_text(text):
                    kws = list(set(_tokenize(chunk)))
                    doc_freq.update(kws)
                    chunks.append({"id": len(chunks), "text": chunk, "source": source, "keywords": kws})
                    if len(chunks) >= self.MAX_CHUNKS:
                        break

        # JSON output files
        if len(chunks) < self.MAX_CHUNKS:
            for fp in _json_files_in(case_path):
                if fp.name == self.INDEX_FILE:
                    continue
                try:
                    raw = fp.read_text(encoding="utf-8", errors="replace")
                    # Try to parse; if it's a dict with "narrative" or "output" keys, use those
                    try:
                        data = json.loads(raw)
                        if isinstance(data, dict):
                            for key in ("narrative", "output", "executive_summary",
                                        "full_written_report", "conclusion"):
                                val = data.get(key)
                                if val and isinstance(val, str):
                                    raw = val
                                    break
                    except json.JSONDecodeError:
                        pass

                    source = f"file:{fp.name}"
                    for chunk in _chunk_text(raw):
                        kws = list(set(_tokenize(chunk)))
                        doc_freq.update(kws)
                        chunks.append({"id": len(chunks), "text": chunk, "source": source, "keywords": kws})
                        if len(chunks) >= self.MAX_CHUNKS:
                            break
                except OSError:
                    pass
                if len(chunks) >= self.MAX_CHUNKS:
                    break

        # Build IDF table
        n_docs = max(len(chunks), 1)
        idf: dict = {w: math.log(n_docs / (1 + cnt)) for w, cnt in doc_freq.items()}

        index = {
            "chunks": chunks,
            "idf": idf,
            "built_at": datetime.utcnow().isoformat(),
            "chunk_count": len(chunks),
        }

        idx_path = self._index_path(case_path)
        try:
            idx_path.parent.mkdir(parents=True, exist_ok=True)
            idx_path.write_text(json.dumps(index, default=str))
        except OSError:
            pass

        return index

    def _load_index(self, case_dir: Path) -> Optional[dict]:
        idx_path = self._index_path(case_dir)
        if not idx_path.exists():
            return None
        try:
            return json.loads(idx_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def _score_chunk(self, chunk: dict, query_tokens: list, idf: dict) -> float:
        """TF-IDF score of a chunk against query tokens."""
        chunk_freq = Counter(chunk.get("keywords", []))
        score = 0.0
        for token in query_tokens:
            tf = chunk_freq.get(token, 0)
            if tf:
                score += (1 + math.log(tf)) * idf.get(token, 0.0)
        return score

    def _retrieve(self, index: dict, question: str, top_k: int = 6) -> list:
        """Return top-k chunks by TF-IDF score."""
        q_tokens = _tokenize(question)
        idf = index.get("idf", {})
        scored = [
            (self._score_chunk(c, q_tokens, idf), c)
            for c in index.get("chunks", [])
        ]
        scored.sort(key=lambda x: -x[0])
        return [c for score, c in scored[:top_k] if score > 0]

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(
        self,
        question: str,
        case_dir: str,
        call_llm_func: Callable,
        top_k: int = 6,
        rebuild: bool = False,
    ) -> dict:
        """Answer a question about the case using retrieved context.

        Args:
            question: Free-form analyst question.
            case_dir: Path to the case work directory.
            call_llm_func: Callable(prompt, agent_type="manager") → str.
            top_k: Number of chunks to retrieve.
            rebuild: Force re-index even if index exists.

        Returns:
            {"answer": str, "sources": [str], "chunks_used": int}
        """
        case_path = Path(case_dir)
        index = None if rebuild else self._load_index(case_path)
        if index is None:
            index = self.index_case(case_dir)

        chunks = self._retrieve(index, question, top_k=top_k)

        if not chunks:
            context = "No relevant findings were retrieved from the case evidence."
        else:
            context_parts = []
            for i, c in enumerate(chunks, 1):
                context_parts.append(f"[{i}] (source: {c['source']})\n{c['text']}")
            context = "\n\n".join(context_parts)

        prompt = (
            "You are a digital forensics analyst (Geoff). "
            "Use only the case evidence excerpts below to answer the analyst's question. "
            "Cite specific evidence where possible. "
            "If the answer cannot be determined from the evidence, say so.\n\n"
            f"CASE EVIDENCE EXCERPTS:\n{context}\n\n"
            f"ANALYST QUESTION: {question}\n\n"
            "ANSWER:"
        )

        try:
            answer = call_llm_func(prompt, agent_type="manager") or "Unable to generate answer."
        except Exception as e:
            answer = f"LLM error: {e}"

        sources = list({c["source"] for c in chunks})
        return {
            "answer": answer,
            "sources": sources,
            "chunks_used": len(chunks),
            "index_chunk_count": index.get("chunk_count", 0),
        }
