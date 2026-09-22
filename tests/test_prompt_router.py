#!/usr/bin/env python3

"""Tests for prompt_router.py BM25 prompt-to-tool routing."""

from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")


def test_tokenize_strips_punctuation():
    from mcp_server.tools.prompt_router import _tokenize
    tokens = _tokenize("Brute-force SSH on mail.server!")
    assert "brute-force" in tokens
    assert "ssh" in tokens
    assert "mail.server" in tokens
    assert "on" in tokens
    tokens2 = _tokenize("a b c")
    assert tokens2 == []


def test_mini_bm25_basic():
    from mcp_server.tools.prompt_router import _MiniBM25
    corpus = [
        "beacon detect C2 callback periodic traffic",
        "alert summarize IoC extraction rule grouping",
        "email lookup compromised account phishing",
    ]
    bm = _MiniBM25(corpus)
    # "beacon" should match doc 0 best
    results = bm.score("beacon")
    assert len(results) > 0
    assert results[0][0] == 0  # first doc
    # "phishing email" should match doc 2 best
    results2 = bm.score("phishing email account")
    assert results2[0][0] == 2


def test_mini_bm25_empty_corpus():
    from mcp_server.tools.prompt_router import _MiniBM25
    bm = _MiniBM25([])
    assert bm.n == 0
    assert bm.score("anything") == []


def test_mini_bm25_idf_rarity():
    from mcp_server.tools.prompt_router import _MiniBM25
    corpus = [
        "alert summary alert alert",
        "alert beacon rare term",
    ]
    bm = _MiniBM25(corpus)
    assert "rare" in bm.idf
    assert "alert" in bm.idf
    assert bm.idf["rare"] > bm.idf["alert"]


def test_router_singleton():
    from mcp_server.tools.prompt_router import _get_router
    r1 = _get_router()
    r2 = _get_router()
    assert r1 is r2


def test_route_mode():
    from mcp_server.tools.prompt_router import _get_router
    router = _get_router()
    results = router.route("brute force SSH authentication", top_k=3)
    assert isinstance(results, list)
    if results:
        assert "tool" in results[0]
        assert "score" in results[0]
        assert "matched_tokens" in results[0]


def test_buckets_mode():
    from mcp_server.tools.prompt_router import _get_router
    router = _get_router()
    result = router.token_buckets("C2 beacon DNS tunneling exfiltration")
    assert "buckets" in result
    assert "unmatched_tokens" in result
    if result["buckets"]:
        first = list(result["buckets"].values())[0]
        assert "tokens" in first
        assert "score" in first


def test_unmatched_tokens_surfaced():
    from mcp_server.tools.prompt_router import _get_router
    router = _get_router()
    result = router.token_buckets("xyzzy_nonexistent_token_abc123")
    all_unmatched = result.get("unmatched_tokens", [])
    assert len(all_unmatched) > 0


def _register_and_reset():
    """Register every tool module once and rebuild the router singleton.
    ``register_all_tools`` is idempotent (module imports are cached), but the
    router caches its corpus at first call, so the singleton is dropped to make
    the test independent of whichever test ran before it. No model is loaded and
    no network is touched: ``_build_tool_corpus`` reads the FastMCP registry.
    """
    import mcp_server.tools.prompt_router as pr
    from mcp_server.tools import register_all_tools
    register_all_tools()
    pr._router = None
    return pr._get_router()


def test_query_expansion_maps_indonesian_to_english():
    """The corpus is English, analysts prompt in Indonesian (P1 lever)."""
    from mcp_server.tools.prompt_router import _expand_query
    out = _expand_query("Buat laporan SOC harian")
    assert "report" in out and "aggregate" in out   # laporan -> report family
    assert "buat" in out                            # unknown token passes through whole
    # function words are dropped, content words are translated
    out2 = _expand_query("alert yang mencurigakan")
    assert "yang" not in out2 and "suspicious" in out2
    # an English prompt gains no Indonesian noise
    assert _expand_query("brute force ssh") == "brute force ssh"


def test_tokenize_contract_unchanged_by_expansion():
    """Expansion lives in _expand_query; _tokenize keeps its documented contract."""
    from mcp_server.tools.prompt_router import _tokenize
    assert _tokenize("a b c") == []
    assert "on" in _tokenize("brute force on mail")
    assert "the" in _tokenize("the report")


def test_corpus_document_includes_docstring_and_param_text():
    """Regression for the P1 finding: documents were name + first paragraph only
    (median 100 chars), and parameter text was never harvested because the schema
    lives on ``parameters``, not ``inputSchema``."""
    router = _register_and_reset()
    assert len(router.tool_corpus) > 100
    total = sum(len(t["text"]) for t in router.tool_corpus)
    assert total > 100_000, f"corpus too thin: {total} chars"
    # the stored document is the full docstring, not the 120 char display summary
    agg = next(t for t in router.tool_corpus if t["name"] == "wazuh_alert_aggregate_analysis")
    assert len(agg["text"]) > len(agg["description"])
    # tools with no docstring still get indexable text from their param schema
    blind = [t for t in router.tool_corpus if t["name"] == "blueteam_wazuh_get_rules"]
    assert blind and "status" in blind[0]["text"]


def test_param_text_resolves_inline_and_ref_schemas():
    """FastMCP wraps the Pydantic input model under one ``params`` property, either
    inlined or behind a ``$ref`` into ``$defs``. Both shapes must yield field text."""
    from mcp_server.tools.prompt_router import _param_text
    inline = {"properties": {"params": {"title": "RulesInput", "properties": {
        "status": {"description": "Filter by status: enabled, disabled, all"},
        "group": {"description": "Filter by rule group"},
    }}}}
    text = _param_text(inline)
    assert "status" in text and "Filter by status" in text
    assert "group" in text and "Filter by rule group" in text

    ref = {"properties": {"params": {"$ref": "#/$defs/Thing"}},
           "$defs": {"Thing": {"properties": {
               "agent_name": {"description": "Optional agent name filter."}}}}}
    ref_text = _param_text(ref)
    assert "agent_name" in ref_text and "Optional agent name filter." in ref_text

    # a schema with no resolvable fields yields empty text, never a crash
    assert _param_text(None) == ""
    assert _param_text({}) == ""
    assert _param_text({"properties": {"params": {"$ref": "#/$defs/Missing"}}}) == ""


def test_domain_synonyms_route_report_prompts_to_pipeline_tools():
    """In this toolset a SOC report means aggregate the window and show the
    timeline; the tools that do that never say "report" in their docstrings."""
    from mcp_server.tools.prompt_router import _expand_query
    out = _expand_query("Write the 24 hour SOC report")
    assert "aggregate" in out and "timeline" in out
    assert "write" not in out          # English stopword dropped from the query
    assert "24" in out                  # window digit survives
    # English stopwords are dropped, unknown technical words pass through
    assert _expand_query("beaconing to c2") == "beaconing c2"
    assert _expand_query("webshell nginx") == "webshell nginx"


def test_route_reranked_slices_docs_and_uses_expanded_query():
    """Stage 2 must see the expanded query and a bounded doc slice. The full
    corpus document is stage-1 material; feeding it to the cross-encoder is what
    pushed p95 from 1.4 s to 4.7 s."""
    import asyncio
    import mcp_server.tools.prompt_router as pr
    router = _register_and_reset()
    captured: dict = {}
    real = pr._cross_rerank

    async def fake_rerank(query, docs):
        captured["query"] = query
        captured["docs"] = list(docs)
        return [1.0 - i * 0.01 for i in range(len(docs))], None

    pr._cross_rerank = fake_rerank
    try:
        results, status = asyncio.run(
            router.route_reranked("cek webshell di server nginx", top_k=3, candidates=5))
    finally:
        pr._cross_rerank = real

    assert status is None
    assert len(captured["docs"]) == 5
    assert all(len(d) <= pr._RERANK_DOC_CHARS for d in captured["docs"])
    assert "check" in captured["query"]          # cek -> check (expansion reached stage 2)
    assert "di" not in captured["query"].split()  # Indonesian stopword dropped
    assert len(results) == 3
    # route_reranked exposes the cross-encoder score as 'score' (with the BM25
    # score kept alongside for tie-breaking visibility)
    assert all("score" in r and "bm25_score" in r and "matched_tokens" in r for r in results)
    assert [r["score"] for r in results] == sorted((r["score"] for r in results), reverse=True)


def test_route_reranked_falls_back_to_bm25_when_disabled():
    """Failure contract: a disabled/unavailable reranker returns the BM25 order
    and a machine-readable status, never an empty result."""
    import asyncio
    from mcp_server.core.config import config
    import mcp_server.tools.prompt_router as pr
    router = _register_and_reset()
    original = config.rerank.enabled
    config.rerank.enabled = False
    try:
        results, status = asyncio.run(router.route_reranked("beacon c2", top_k=3, candidates=5))
    finally:
        config.rerank.enabled = original
    assert status == "disabled"
    assert results, "fallback must not be empty when BM25 matched"
    assert [r["tool"] for r in results] == [r["tool"] for r in router.route("beacon c2", top_k=3)]
    assert all("rerank_score" not in r for r in results)


def test_prompt_route_labels_itself_when_no_model_is_cached(tmp_path):
    """Staging contract: the server must run on a host with no model cache.
    A SHA pin forces ``local_files_only``, so a cold cache is a load error and never a
    download, and the response must still carry BM25 results labelled ``bm25`` with the
    reason. This is the path every test in this file relies on, asserted instead of
    assumed. Works with fastembed absent too: that raises inside the same guard.
    """
    import asyncio
    import json
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    import mcp_server.tools.prompt_router as pr
    _register_and_reset()

    rerank._encoder = None
    rerank._reason = "not loaded"
    saved = (config.rerank.enabled, config.rerank.cache_path, config.rerank.sha256)
    config.rerank.enabled = True
    config.rerank.cache_path = str(tmp_path)   # empty: nothing is cached here
    config.rerank.sha256 = "0" * 64            # pin present -> no runtime egress
    try:
        out = json.loads(asyncio.run(pr.blueteam_prompt_route(
            pr.PromptRouteInput(prompt="brute force ssh mail server", rerank=True))))
    finally:
        (config.rerank.enabled, config.rerank.cache_path, config.rerank.sha256) = saved
        rerank._encoder = None
        rerank._reason = "not loaded"

    assert out["rerank_used"] is False
    assert out["rerank_engine"] == "bm25"
    assert out["rerank_status"].startswith("unavailable:"), out["rerank_status"]
    assert out["results"], "a cold model cache must not empty the routing shortlist"
    assert not list(tmp_path.rglob("*.onnx")), (
        "the pinned path downloaded model weights instead of failing closed"
    )


def test_prompt_route_tool_output_contract():
    """Tool-level contract: the response names the engine that ranked it and
    echoes the expanded query, without touching the model (rerank is opt-in)."""
    import asyncio
    import json
    import mcp_server.tools.prompt_router as pr
    _register_and_reset()
    out = json.loads(asyncio.run(pr.blueteam_prompt_route(
        pr.PromptRouteInput(prompt="cek apakah IP ini masuk blocklist sangfor"))))
    assert out["mode"] == "route"
    assert out["tools_indexed"] > 100
    assert "check" in out["query_expanded"]
    assert out["rerank_engine"] == "bm25"
    assert out["rerank_status"] == "not_requested"
    assert out["rerank_used"] is False
    assert out["results"] and "matched_tokens" in out["results"][0]
    assert out["results"][0]["tool"].startswith("sangfor_blocklist")


def test_buckets_mode_groups_expanded_tokens():
    """Buckets are a debug view: they must show the expansion that routed the
    prompt, so an empty shortlist can be diagnosed without guessing."""
    import asyncio
    import json
    import mcp_server.tools.prompt_router as pr
    _register_and_reset()
    out = json.loads(asyncio.run(pr.blueteam_prompt_route(
        pr.PromptRouteInput(prompt="webshell mencurigakan di server nginx", mode="buckets"))))
    assert out["mode"] == "buckets"
    tokens = [t for bucket in out["buckets"].values() for t in bucket["tokens"]]
    assert "webshell" in tokens
    assert "suspicious" in tokens                   # mencurigakan -> suspicious
    assert not [b for b in ["di"] if b in tokens]   # stopword dropped


EXPECTED_LABELLED_PROMPTS = 22
RECALL_FLOOR_K = 10


def test_labelled_prompt_recall_floor():
    """Every labelled prompt must keep an acceptable tool inside BM25 top-10.
    A failure here means the alias map or the corpus document shrank, not that the
    ranking got slightly worse: this is the precondition for any ranking work.
    """
    from tests.bench_rerank_routing import PROMPTS
    router = _register_and_reset()

    assert len(PROMPTS) == EXPECTED_LABELLED_PROMPTS, (
        f"labelled prompt set changed size ({len(PROMPTS)}). Re-baseline the floor below "
        f"deliberately rather than letting the assertion shrink with the file."
    )
    corpus = {t["name"] for t in router.tool_corpus}
    stale = sorted({tool for *_, accepted in PROMPTS for tool in accepted} - corpus)
    assert not stale, (
        f"labels reference tools that are not in the corpus (renamed or removed?): {stale}"
    )

    misses = []
    for pid, lang, prompt, accepted in PROMPTS:
        top = {h["tool"] for h in router.route(prompt, top_k=RECALL_FLOOR_K)}
        if not (top & accepted):
            misses.append((pid, lang, prompt, sorted(accepted)))
    assert not misses, (
        f"BM25 top-{RECALL_FLOOR_K} lost the acceptable tool for {len(misses)} labelled "
        f"prompt(s); no reranker can reorder a window the tool is not in:\n"
        + "\n".join(f"  {p} [{l}] {q!r} expected one of {a}" for p, l, q, a in misses)
    )


if __name__ == "__main__":
    import sys
    import traceback
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            globals()[t]()
            print(f"PASS {t}")
            passed += 1
        except Exception:
            print(f"FAIL {t}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
