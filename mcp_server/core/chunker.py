#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Text normalisation and sentence-aware chunking for the RAG ingest path.
Algorithms ported from RAGFlow (Apache-2.0), `internal/parser/chunk/preprocess.go`,
`split.go` and `postprocess.go`. Replaces the fixed character window in
`tools/rag_kb.py`, which cut sentences in half: a chunk starting mid-clause embeds
as noise and matches nothing. Pure stdlib, no model, no network, so the ingest path stays inside the egress
guarantee documented on ``RAGConfig``. Nothing here loads at import time.
"""
from __future__ import annotations
import re

# RAGFlow's terminators plus the CJK full-width forms. Newline is included because
# ``normalize()`` already emits one sentence per line.
_CJK_BOUNDARIES = "。！？"
_ASCII_BOUNDARIES = ".!?;"

# CJK terminators need no trailing space; ASCII ones do. Requiring whitespace after
# an ASCII terminator is what keeps `8.8.8.8` and `v1.2.3` in one piece.
_SENT_RE = re.compile(rf"[{_CJK_BOUNDARIES}]|[{_ASCII_BOUNDARIES}](?=\s|$)|\n+")
_SENTENCE_END = re.compile(r"[.!?][\s]*$")
_MULTI_NEWLINE = re.compile(r"\n{2,}")

DEFAULT_CHUNK_SIZE = 256
DEFAULT_STRATEGY = "sentences"
STRATEGIES = ("sentences", "paragraphs", "length")


def normalize(text: str) -> str:
    """Normalise extracted text before chunking.
    The soft line-break merge is the point. PDF extractors hard-wrap mid-sentence,
    so ``"the attacker moved\\nlaterally"`` arrives as two lines and neither line
    carries the phrase a query would match. Lines are joined until one ends in
    sentence punctuation.
    Collapsing blank lines discards paragraph structure. That is acceptable for
    PDF page text (the intended caller); a caller ingesting structured markdown
    should skip this and call ``split`` directly.
    """
    body = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    body = _MULTI_NEWLINE.sub("\n", body)
    lines = [line.strip() for line in body.split("\n")]
    lines = [line for line in lines if line]

    merged: list[str] = []
    buf: list[str] = []
    for idx, line in enumerate(lines):
        buf.append(line)
        if idx == len(lines) - 1 or _SENTENCE_END.search(line):
            merged.append(" ".join(buf))
            buf = []
    return "\n".join(merged)


def _split_sentences(text: str) -> list[str]:
    """Split on sentence terminators, keeping the terminator with its sentence.
    ASCII terminators require trailing whitespace. Splitting on a bare ``.`` would
    shred the IOC text this corpus is full of: ``8.8.8.8``, ``v1.2.3``, ``10.20.30.40``.
    """
    out: list[str] = []
    start = 0
    for match in _SENT_RE.finditer(text):
        piece = text[start:match.end()].strip()
        if piece:
            out.append(piece)
        start = match.end()
    tail = text[start:].strip()
    if tail:
        out.append(tail)
    return out


def _split_paragraphs(text: str) -> list[str]:
    return [p.strip() for p in text.split("\n") if p.strip()]


def _split_length(text: str, size: int, overlap: int) -> list[str]:
    """Fixed rune window with carry-over.
    The pre-port behaviour, kept as a fallback so reverting a deployment is a
    config change rather than a code change.
    """
    if len(text) <= size:
        return [text] if text.strip() else []
    out: list[str] = []
    step = max(1, size - overlap)
    for start in range(0, len(text), step):
        piece = text[start:start + size].strip()
        if piece:
            out.append(piece)
        if start + size >= len(text):
            break
    return out


def _pack(units: list[str], size: int, overlap: int) -> list[str]:
    """Greedily merge units into chunks of at most ``size`` runes.
    Overlap carries back whole trailing units, never a mid-unit slice, so the
    carried text is always complete sentences.
    A unit longer than ``size`` is windowed by ``_split_length``. Emitting it whole
    would hand the embedder a chunk past its max sequence length, which truncates
    silently: the tail of that chunk is then stored but unmatchable, and nothing in
    the response says so.
    """
    out: list[str] = []
    buf: list[str] = []
    buf_len = 0

    for unit in units:
        unit_len = len(unit)
        if unit_len >= size:
            if buf:
                out.append(" ".join(buf))
                buf, buf_len = [], 0
            out.extend(_split_length(unit, size, overlap))
            continue

        if buf and buf_len + unit_len + 1 > size:
            out.append(" ".join(buf))
            carry: list[str] = []
            carry_len = 0
            for prev in reversed(buf):
                if carry_len + len(prev) + 1 > overlap:
                    break
                carry.insert(0, prev)
                carry_len += len(prev) + 1
            buf, buf_len = carry, carry_len

        buf.append(unit)
        buf_len += unit_len + 1

    if buf:
        out.append(" ".join(buf))
    return out


def split(text: str, *, size: int = DEFAULT_CHUNK_SIZE, overlap: int = 0,
          strategy: str = DEFAULT_STRATEGY) -> list[str]:
    """Chunk ``text`` into pieces of at most ``size`` runes.
    Sizing is by rune count, matching ``len()`` on a Python str, so multi-byte
    text windows by character rather than by byte. ``overlap`` is clamped below
    ``size`` so the window always advances.
    An unknown ``strategy`` falls back to ``sentences`` rather than raising: a
    typo'd env var should degrade retrieval quality, not block ingest.
    """
    body = (text or "").strip()
    if not body:
        return []

    size = max(1, size)
    overlap = max(0, min(overlap, size // 2))

    if strategy == "length":
        return _split_length(body, size, overlap)

    units = _split_paragraphs(body) if strategy == "paragraphs" else _split_sentences(body)
    return _pack(units, size, overlap) if units else []
