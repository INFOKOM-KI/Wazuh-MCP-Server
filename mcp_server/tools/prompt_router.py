#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Prompt-to-tool routing via BM25 lexical ranking over MCP tool descriptions.
Without external dependencies; stdlib-only BM25 reuses the pattern from semantic_search.py.
Given a natural language security prompt (e.g. "brute force SSH on mail server"),
tokenizes it, scores each token's IDF against the tool corpus, buckets tokens by
their strongest tool association, and returns a ranked tool invocation plan.
The corpus the BM25 index is built from carries the FULL tool docstring plus the
Pydantic field names/descriptions of the tool's input model, and the query is
expanded with an Indonesian -> English vocabulary map before scoring, because the
corpus vocabulary is English and analysts prompt in both languages.
"""
from __future__ import annotations
import json, math, re, logging
from collections import defaultdict
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp
from mcp_server.core.rerank import rerank as _cross_rerank, status_dict

logger = logging.getLogger("blue_team_mcp.prompt_router")

# BM25 + tokenizer
_K1 = 1.5
_B = 0.75

# Per-tool document caps. Both bound BM25 doc length and rerank input size: the
# corpus is English, the prompts are not, and a 146-tool BM25 index is cheap at
# any length while the cross-encoder is not (its cost scales with token count).
_MAX_DOC_CHARS = 2000       # stored corpus text per tool
_RERANK_DOC_CHARS = 600     # slice handed to the cross-encoder (recall text != rerank text)


def _tokenize(text: str) -> list[str]:
    """Lowercase, split, remove short tokens and punctuation."""
    text = re.sub(r"[^a-z0-9\s._-]", " ", text.lower())
    return [t.strip("._-") for t in text.split() if len(t.strip("._-")) >= 2]


# Indonesian -> English query expansion. Tool names and docstrings are English,
# so an Indonesian prompt only reaches a tool if the English vocabulary it maps
# to is in the query. Values are English expansion terms, space separated.
_ID_EN_ALIASES: dict[str, str] = {
    "laporan": "report summary aggregate",
    "laporkan": "report",
    "harian": "daily 24h",
    "mingguan": "weekly 7d",
    "bulanan": "monthly 30d",
    "kuartalan": "quarterly 90d",
    "tahunan": "annual yearly 365d",
    "serangan": "attack",
    "menyerang": "attack",
    "menyerangnya": "attack",
    "serang": "attack",
    "penyerang": "attacker",
    "bocor": "breach leak credentials",
    "kebocoran": "breach leak",
    "kredensial": "credentials password",
    "sandi": "password",
    "kerentanan": "vulnerability cve",
    "celah": "vulnerability cve",
    "aturan": "rule rules",
    "agen": "agent",
    "gagal": "failed",
    "masuk": "login",
    "pengguna": "user account",
    "berkas": "file",
    "proses": "process",
    "koneksi": "connection connections",
    "port": "port listening",
    "terbuka": "open",
    "pindai": "scan scanning",
    "pemindaian": "scan scanning",
    "pemantauan": "monitoring",
    "mencurigakan": "suspicious",
    "kecurigaan": "suspicious",
    "lonjakan": "spike drift baseline",
    "tren": "trend velocity",
    "sebaran": "distribution geo",
    "peta": "map geo",
    "sertifikat": "certificate tls jarm",
    "sidik": "fingerprint jarm",
    "jari": "fingerprint jarm",
    "kasus": "case incident",
    "investigasi": "investigation",
    "tindak": "playbook response",
    "lanjut": "playbook followup",
    "blokir": "block blocklist",
    "daftar": "list",
    "jaringan": "network",
    "ambil": "get fetch",
    "lihat": "list get show",
    "tampilkan": "list get show",
    "cari": "search lookup find",
    "cek": "check lookup",
    "periksa": "check",
    "waktu": "time timeline",
    "kecepatan": "velocity",
    "hari": "day",
    "jam": "hour",
    "pencuri": "stealer",
    "pencurian": "stealer theft",
    "sumber": "source srcip",
    "tujuan": "destination",
    "reputasi": "reputation",
    "skor": "score",
    "nilai": "score",
    "perangkat": "agent device",
    "kepatuhan": "compliance sca",
    "kebijakan": "policy",
    "izin": "permission privilege",
    "hak": "privilege access",
    "akses": "access",
    "jadwal": "cron schedule",
    "tugas": "cron job task",
    "mirip": "lookalike permute",
    "palsu": "false positive",
    "positif": "positive",
    "negatif": "negative",
    "dokumen": "document pdf",
    "lampiran": "attachment document",
    "trafik": "traffic",
    "malware": "malware hash",
    "sertifikatnya": "certificate tls",
    "surel": "email",
    "akun": "account",
    "klaster": "cluster nodes",
    "simpul": "cluster nodes",
    "basis": "database",
    "sistem": "system host",
    "layanan": "service",
    "kunci": "key credential",
    "enkripsi": "encryption ransomware",
    "biner": "binary",
    "jaringan": "network firewall",
    "fw": "firewall",
    "penuh": "full",
}

# Indonesian function words plus English ones: dropped from the expanded query only.
# They carry no IDF signal against the tool corpus and dilute the BM25 score
# (longer documents after enrichment mean common words are matched many times).
# Deliberately NOT applied inside ``_tokenize``, whose token contract other
# callers depend on.
_QUERY_STOPWORDS: frozenset[str] = frozenset({
    "yang", "untuk", "ini", "itu", "ada", "tidak", "bukan", "saja",
    "apa", "apakah", "siapa", "mana", "berapa", "kapan", "di", "ke",
    "dari", "dan", "atau", "dengan", "pada", "dalam", "oleh", "juga",
    "masih", "sudah", "belum", "bisa", "dapat", "kami", "kita", "saya",
    "mereka", "dulu", "lagi", "sangat", "paling", "semua", "tiap",
    "setiap", "punya", "pernah", "mau", "tolong", "nih", "nya", "lah",
    "the", "a", "an", "of", "to", "is", "are", "was", "were", "be",
    "has", "have", "had", "that", "this", "these", "those", "it", "its",
    "as", "at", "on", "if", "then", "than", "so", "up", "out", "we",
    "you", "what", "which", "when", "where", "who", "how", "can", "will",
    "would", "should", "do", "does", "did", "any", "some", "no", "write",
})

# English -> English domain synonyms, hand-curated for THIS toolset (146 tools).
# A SOC report in this deployment means aggregate the alert window and show the
# timeline: the tools that do that never say "report" in their docstring, and the
# tools that do say "report" are exporters. Values are English expansion terms.
_DOMAIN_SYNONYMS: dict[str, str] = {
    "report": "aggregate timeline summary",
    "laporan": "aggregate timeline summary",
    "soc": "aggregate timeline",
    "summary": "aggregate summarize",
}


def _expand_query(text: str) -> str:
    """Append English expansion terms for Indonesian tokens in ``text``.
    Prompts are passed through unchanged apart from stopword removal and the
    appended expansions, so an English prompt scores exactly as before.
    """
    tokens = _tokenize(text)
    expanded = [t for t in tokens if t not in _QUERY_STOPWORDS]
    for token in tokens:
        expansion = _ID_EN_ALIASES.get(token) or _DOMAIN_SYNONYMS.get(token)
        if expansion:
            expanded.extend(expansion.split())
    return " ".join(expanded)

class _MiniBM25:
    """Minimal BM25 Okapi scorer; same math as semantic_search._BM25."""
    def __init__(self, corpus: list[str]):
        self.corpus = corpus
        self.n = len(corpus)
        self.tokenized = [_tokenize(d) for d in corpus]
        self.doc_len = [len(t) for t in self.tokenized]
        self.avgdl = sum(self.doc_len) / max(self.n, 1) or 1e-9
        df: dict[str, int] = defaultdict(int)
        for tokens in self.tokenized:
            for t in set(tokens):
                df[t] += 1
        self.idf = {t: math.log((self.n - c + 0.5) / (c + 0.5) + 1)
                     for t, c in df.items()}

    def score(self, query: str) -> list[tuple[int, float]]:
        q_tokens = _tokenize(_expand_query(query))
        scores: list[tuple[int, float]] = []
        for idx, doc_tokens in enumerate(self.tokenized):
            dl = self.doc_len[idx]
            if dl == 0:
                continue
            tf: dict[str, int] = {}
            for t in doc_tokens:
                tf[t] = tf.get(t, 0) + 1
            score = 0.0
            for qt in q_tokens:
                if qt not in self.idf:
                    continue
                f = tf.get(qt, 0)
                if f == 0:
                    continue
                tfv = f * (_K1 + 1) / (f + _K1 * (1 - _B + _B * dl / self.avgdl))
                score += self.idf[qt] * tfv
            if score > 0:
                scores.append((idx, score))
        scores.sort(key=lambda x: -x[1])
        return scores


# Tool corpus builder
def _param_text(schema: dict | None) -> str:
    """Field names + field descriptions from a tool's JSON parameter schema.
    FastMCP wraps the Pydantic input model under a single ``params`` property,
    often as a ``$ref`` into ``$defs``; both shapes are resolved here. Field
    descriptions are the richest vocabulary source in the registry: they spell
    out what an analyst would call the thing ("Filter by rule group", "ISO 8601
    start time in UTC").
    """
    schema = schema or {}
    props = (schema.get("properties") or {})
    inner = props.get("params") if isinstance(props.get("params"), dict) else schema
    ref = (inner or {}).get("$ref")
    if ref:
        inner = ((schema.get("$defs") or {}).get(str(ref).split("/")[-1]) or {})
    fields = (inner or {}).get("properties") or {}
    parts = [str(inner.get("title") or ""), str(inner.get("description") or "")]
    for fname, spec in fields.items():
        parts.append(str(fname))
        if isinstance(spec, dict) and spec.get("description"):
            parts.append(str(spec["description"]))
    return " ".join(p for p in parts if p).strip()


def _build_tool_corpus() -> list[dict]:
    """Harvest tool name + FULL docstring + param schema text from the registry.
    Returns a list of dicts with keys: name, description, text (the BM25 document).
    Built lazily on first call so all @mcp.tool decorators have fired.

    The document is the whole docstring (worked examples and caveats included),
    not just the summary line: the summary is often ~100 characters, which leaves
    a lexical ranker nothing to match an analyst's phrasing against. Tool objects
    in the FastMCP tool manager expose the schema as ``parameters`` (the MCP
    ``inputSchema`` name does not exist on this class) - reading the wrong
    attribute silently indexes parameter-less documents.
    """
    tools: list[dict] = []
    try:
        registered = getattr(mcp._tool_manager, "_tools", {})
    except Exception:
        registered = {}
    for name, tool in sorted(registered.items()):
        fn = getattr(tool, "fn", None)
        desc = (getattr(tool, "description", "") or "").strip()
        if not desc and fn is not None:
            desc = (getattr(fn, "__doc__", "") or "").strip()
        first_para = desc.split("\n\n")[0] if desc else ""
        schema = getattr(tool, "parameters", None) or {}
        param_str = _param_text(schema)
        text = " ".join(filter(None, [
            name.replace("_", " "),
            desc[:_MAX_DOC_CHARS],
            param_str,
        ]))
        tools.append({
            "name": name,
            # Short summary for display; falls back to the param text so a tool
            # with no docstring is not shown as a blank result row.
            "description": (first_para or param_str)[:120],
            "text": text,
        })
    return tools


# Prompt Router
class PromptRouter:
    """BM25-based prompt-to-tool router.
    Builds a BM25 index over all registered MCP tool descriptions at init time.
    ``route()`` returns ranked tool suggestions. ``token_buckets()`` groups prompt
    words by their strongest tool association.
    """

    def __init__(self):
        self.tool_corpus: list[dict] = _build_tool_corpus()
        corpus_texts = [t["text"] for t in self.tool_corpus]
        self.bm25 = _MiniBM25(corpus_texts) if corpus_texts else None
        logger.info("PromptRouter: %d tools indexed", len(self.tool_corpus))

    def route(self, prompt: str, top_k: int = 5) -> list[dict]:
        """Rank tools by BM25 relevance to the prompt. Returns top-K matches."""
        if not self.bm25 or not self.tool_corpus:
            return []
        results = []
        for idx, score in self.bm25.score(prompt)[:top_k]:
            t = self.tool_corpus[idx]
            # Find which query tokens (expansions included) matched this tool
            prompt_tokens = set(_tokenize(_expand_query(prompt)))
            doc_tokens = set(self.bm25.tokenized[idx])
            matched = sorted(prompt_tokens & doc_tokens)
            results.append({
                "rank": len(results) + 1,
                "tool": t["name"],
                "score": round(score, 2),
                "description": t["description"],
                "matched_tokens": matched,
            })
        return results

    def expanded(self, prompt: str) -> str:
        """The query as the rankers see it (stopwords dropped, ID terms expanded).
        Surfaced in tool output so an empty shortlist can be diagnosed without
        guessing whether the analyst's wording or the corpus is at fault.
        """
        return _expand_query(prompt)

    def _matched_tokens(self, prompt: str, idx: int) -> list[str]:
        """Query tokens (expansions included) present in the indexed document."""
        return sorted(set(_tokenize(_expand_query(prompt))) & set(self.bm25.tokenized[idx]))

    async def route_reranked(self, prompt: str, top_k: int,
                             candidates: int = 20) -> tuple[list[dict], str | None]:
        """BM25 top-M recall + cross-encoder rerank, truncated to top-K.
        Returns ``(results, status)``; ``status`` is ``None`` on success, else a
        short fallback reason ("disabled"/"unavailable: …"/"empty"). On fallback
        the results are the plain BM25 top-K from ``route()``.
        """
        if not self.bm25 or not self.tool_corpus:
            return [], "empty"
        m = min(max(top_k, candidates), len(self.tool_corpus))
        bm25_hits = self.bm25.score(prompt)[:m]
        if not bm25_hits:
            return [], "empty"
        indices = [idx for idx, _ in bm25_hits]
        bm25_by_idx = dict(bm25_hits)
        # Stage 2 sees a bounded slice, not the whole corpus document: the
        # cross-encoder's cost grows with token count, and the leading sentence
        # or two carries the tool's purpose. Stage 1 keeps the full text.
        docs = [self.tool_corpus[idx]["text"][:_RERANK_DOC_CHARS] for idx in indices]
        scores, status = await _cross_rerank(self.expanded(prompt), docs)
        if status is not None:
            return self.route(prompt, top_k=top_k), status
        # Reorder by cross-encoder score desc, tie-break by BM25 score.
        order = sorted(range(len(indices)),
                       key=lambda i: (-scores[i], -bm25_by_idx[indices[i]]))
        results = []
        for rank, i in enumerate(order[:top_k], 1):
            idx = indices[i]
            t = self.tool_corpus[idx]
            results.append({
                "rank": rank,
                "tool": t["name"],
                "score": round(scores[i], 4),
                "bm25_score": round(bm25_by_idx[idx], 4),
                "description": t["description"],
                "matched_tokens": self._matched_tokens(prompt, idx),
            })
        return results, None

    def token_buckets(self, prompt: str) -> dict:
        """Group prompt tokens into buckets by their strongest tool association.
        Each token is assigned to the tool whose corpus document gives it the
        highest TF (term frequency). Buckets are sorted by combined IDF score.
        """
        tokens = _tokenize(_expand_query(prompt))
        if not self.bm25 or not self.tool_corpus:
            return {"buckets": {}, "unmatched_tokens": tokens}

        buckets: dict[str, dict] = {}
        unmatched: list[str] = []

        for token in tokens:
            if token not in self.bm25.idf:
                unmatched.append(token)
                continue
            # Find which tool doc gives this token the highest TF
            best_tool = None
            best_tf = 0.0
            for i, doc_tokens in enumerate(self.bm25.tokenized):
                if len(doc_tokens) == 0:
                    continue
                tf = doc_tokens.count(token) / len(doc_tokens)
                if tf > best_tf:
                    best_tf = tf
                    best_tool = self.tool_corpus[i]["name"]
            if best_tool:
                buckets.setdefault(best_tool, {"tokens": [], "score": 0.0,
                                               "description": ""})
                buckets[best_tool]["tokens"].append(token)
                buckets[best_tool]["score"] += self.bm25.idf[token]
                if not buckets[best_tool]["description"]:
                    for t in self.tool_corpus:
                        if t["name"] == best_tool:
                            buckets[best_tool]["description"] = t["description"]
                            break

        # Sort buckets by score descending
        sorted_buckets = dict(
            sorted(buckets.items(), key=lambda x: -x[1]["score"])
        )
        # Round scores
        for v in sorted_buckets.values():
            v["score"] = round(v["score"], 2)

        return {"buckets": sorted_buckets, "unmatched_tokens": unmatched}


# Singleton built on first tool call
_router: PromptRouter | None = None


def _get_router() -> PromptRouter:
    global _router
    if _router is None:
        _router = PromptRouter()
    return _router


# MCP Tool
class PromptRouteInput(BaseModel):
    """Input model for blueteam_prompt_route."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    prompt: str = Field(
        ..., min_length=3, max_length=1024,
        description="Natural-language security prompt to route to Wazuh tools.",
    )
    mode: str = Field(
        default="route",
        description="'route' = ranked tool list, 'buckets' = token-to-tool grouping.",
    )
    top_k: int = Field(
        default=5, ge=1, le=20,
        description="Max tools to return in 'route' mode.",
    )
    rerank: bool = Field(
        default=False,
        description="Re-rank BM25 candidates with the local cross-encoder "
                    "(BAAI/bge-reranker-base). OFF by default for routing: measured "
                    "2026-09-21, it made Indonesian top-3 routing worse (7/16 -> 5/16) "
                    "and cost 2.97 s median / 9.67 s p95 per call. English routing is "
                    "unaffected either way. Set true to opt in; rerank_status says why "
                    "when it does not run.",
    )


@mcp.tool(
    name="blueteam_prompt_route",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_prompt_route(params: PromptRouteInput) -> str:
    """Map a natural language security prompt to the most relevant Wazuh MCP tools.
    Uses BM25 lexical ranking over all registered tool descriptions, with an
    optional cross-encoder rerank pass (``rerank=True``) for semantic matching.
    The corpus document per tool is the full docstring plus its input model's
    field names and descriptions, and Indonesian prompts are expanded with an
    English vocabulary map (``query_expanded`` in the response) before scoring -
    an Indonesian question only reaches an English tool description if the terms
    it maps to are in the query. Rerank is NOT on by default here: a 2026-09-21 measurement on 22 labelled
    prompts showed it lowered Indonesian top-3 accuracy (7/16 -> 5/16) while
    costing 2.97 s median per call, because bge-reranker-base scores Indonesian
    queries flat and negative. BM25 recall is the limiter on this corpus, not
    ranking: a tool the query cannot lexically reach (docstring lacks the
    vocabulary) is never in the candidate set the reranker sees. Breaks the prompt
    into key terms, scores each against the tool corpus, and returns a ranked list
    of suggested tools. In 'buckets' mode, groups prompt words by their strongest
    tool association. Every response states which engine ranked it via
    ``rerank_engine`` / ``rerank_status``.

    **Worked Examples**

    1. *Route a brute-force prompt*:
       ``blueteam_prompt_route(prompt="brute force SSH on mail server")``

    2. *Token bucketing for workflow planning*:
       ``blueteam_prompt_route(prompt="C2 beaconing with DNS tunneling", mode="buckets")``

    3. *Top-10 tools for ransomware investigation*:
       ``blueteam_prompt_route(prompt="ransomware encryption files locked", top_k=10)``

    4. *Semantic rerank of a cross-lingual prompt (Indonesia)*:
       ``blueteam_prompt_route(prompt="Cek apakah IP masuk blocklist Sangfor", rerank=True)``
    """
    router = _get_router()

    if params.mode == "buckets":
        result = router.token_buckets(params.prompt)
        return json.dumps({
            "prompt": params.prompt,
            "mode": "buckets",
            **result,
        }, indent=2, ensure_ascii=False)

    if params.rerank:
        ranked, status = await router.route_reranked(
            params.prompt, top_k=params.top_k)
        return json.dumps({
            "prompt": params.prompt,
            "query_expanded": router.expanded(params.prompt),
            "mode": "route",
            **status_dict(status),
            "tools_indexed": len(router.tool_corpus),
            "results": ranked,
        }, indent=2, ensure_ascii=False)

    # Default: route mode (BM25 only)
    ranked = router.route(params.prompt, top_k=params.top_k)
    return json.dumps({
        "prompt": params.prompt,
        "query_expanded": router.expanded(params.prompt),
        "mode": "route",
        **status_dict("not_requested"),
        "tools_indexed": len(router.tool_corpus),
        "results": ranked,
    }, indent=2, ensure_ascii=False)
