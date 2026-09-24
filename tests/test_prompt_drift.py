#!/usr/bin/env python3
"""
Drift guard for the 12 SOC report prompts in resource/your_prompthings/.
These are static files, not generated. When the tool set, the shared RapidAPI budget, or
the quota-free-vs-metered split changes, the prompts go stale silently and the LLM keeps
calling a product the account pays for by the month.
Each test encodes one property that was wrong on 2026-09-14 and has no other
enforcement. Run: pytest tests/test_prompt_drift.py -q
"""
from __future__ import annotations
import os
import pathlib
import re
import pytest

# mcp_server/__init__.py runs init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them here so the rerank-default check
# below passes when this file runs alone, not only after a peer module imported.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

PROMPT_DIR = pathlib.Path(__file__).resolve().parent.parent / "resource" / "your_prompthings"
SKILL_PATH = pathlib.Path(__file__).resolve().parent.parent / "resource" / "skill" / "soc-analysis.md"
README_PATH = pathlib.Path(__file__).resolve().parent.parent / "README.md"

# Every prompt window both languages. Hardcoded so a deleted or renamed file
# fails loudly instead of shrinking the parametrize list to nothing.
EXPECTED_FILES = [
    "your_saving_prompt_24h_en.md", "your_saving_prompt_24h_id.md",
    "your_saving_prompt_3d_en.md", "your_saving_prompt_3d_id.md",
    "your_saving_prompt_7d_en.md", "your_saving_prompt_7d_id.md",
    "your_saving_prompt_30d_en.md", "your_saving_prompt_30d_id.md",
    "your_saving_prompt_90d_en.md", "your_saving_prompt_90d_id.md",
    "your_saving_prompt_1yr_en.md", "your_saving_prompt_1yr_id.md",
]

# Every RapidAPI product draws on ONE account-wide pool (`BLUETEAM_RAPIDAPI_MONTHLY_CAP`,
# default 100/month), and the guard is fail-closed unless the operator armed it for an
# incident window. So the scheduled reports must not advertise any of these: they would
# be refused every run. Keeping them out of the prompt tables is not enough on its own,
# because blueteam_prompt_route and blueteam_semantic_search can surface an unlisted
# tool, so the budget note below carries the refusal reason the guard actually returns.
# Apiverve IP Blacklist was deleted outright on 2026-09-22 and stays listed here so a
# reintroduction cannot quietly become an advertised, unsubscribed call again.
RAPIDAPI_TOOLS = ("blueteam_ioc_search", "blueteam_ioc_search_bulk",
                  "blueteam_ip_intel_bulk", "blueteam_breach_check")
METERED_MARKER = re.compile(r"\(metered, RapidAPI\)")
QUOTA_FREE_TOOLS = ("blueteam_threat_intel_aggregate", "crowdsec_ip_reputation",
                    "threatfox_ioc_search")

THREAT_INTEL_LABELS = {"Intel ancaman", "Threat intel"}
REPORTING_LABELS = {"Pelaporan & intelijen", "Reporting & intelligence"}
BUDGET_NOTE_PREFIXES = ("> RapidAPI budget:", "> Anggaran RapidAPI:")


def _read(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def _rows(text: str) -> dict[str, str]:
    """Map table-row label -> full row line. Label is the first cell."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("|"):
            cells = line.split("|")
            if len(cells) > 2:
                out[cells[1].strip()] = line
    return out


def _notes(text: str) -> list[str]:
    return [l for l in text.splitlines() if l.startswith("> ")]


def _rules(text: str) -> list[tuple[int, str]]:
    """Parse the numbered Rules list into [(number, body)]. Stops at the next heading."""
    out: list[tuple[int, str]] = []
    in_rules = False
    for line in text.splitlines():
        if line.startswith("## Rules"):
            in_rules = True
            continue
        if in_rules and line.startswith("##"):
            break
        if in_rules:
            m = re.match(r"^(\d+)\. (.+)$", line)
            if m:
                out.append((int(m.group(1)), m.group(2)))
    return out


# The file set itself
def test_readme_prompt_block_matches_the_canonical_skill():
    """README embeds a copy of the skill body and declares the skill canonical.
    Left unchecked the two drift apart silently: they were 153 lines apart on 2026-09-14,
    with README still advertising the shared 'http' circuit-breaker pool.
    Fix by regenerating the block, never by editing the copy.
    """
    skill = SKILL_PATH.read_text(encoding="utf-8")
    end = skill.index("\n---\n", 3) + len("\n---\n") if skill.startswith("---\n") else 0
    body = skill[end:].strip("\n")

    lines = README_PATH.read_text(encoding="utf-8").splitlines()
    header = next(i for i, l in enumerate(lines) if l.startswith("## SOC Analysis Prompt"))
    open_i = next(i for i in range(header, len(lines)) if lines[i].strip() == "````markdown")
    close_i = next(i for i in range(open_i + 1, len(lines)) if lines[i].strip() == "````")
    block = "\n".join(lines[open_i + 1:close_i]).strip("\n")
    assert block == body, (
        "README's SOC Analysis Prompt block is stale. Regenerate it from "
        "resource/skill/soc-analysis.md (that file is the source of truth)."
    )


def test_all_twelve_prompt_files_exist():
    missing = [f for f in EXPECTED_FILES if not (PROMPT_DIR / f).is_file()]
    assert not missing, f"prompt files missing from {PROMPT_DIR}: {missing}"
    found = {p.name for p in PROMPT_DIR.glob("*.md")}
    assert found == set(EXPECTED_FILES), f"unexpected prompt files: {found - set(EXPECTED_FILES)}"


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_no_metered_marker_remains(name):
    """The `(metered, RapidAPI)` marker advertised a tool the report run cannot pay for,
    and it was the only thing stopping a stale prompt from looking current."""
    assert not METERED_MARKER.search(_read(name)), f"{name}: metered marker came back"


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_rapidapi_tools_stay_out_of_the_report_prompts(name):
    """A RapidAPI tool may only appear inside the budget note, and only to say it is
    refused. Anywhere else it reads as an available capability."""
    text = _read(name)
    rows = _rows(text)
    for tool in RAPIDAPI_TOOLS:
        holders = [label for label, line in rows.items() if f"`{tool}`" in line]
        assert not holders, f"{name}: {tool} back in the tool table under {holders}"

    for line in text.splitlines():
        if any(f"`{tool}`" in line for tool in RAPIDAPI_TOOLS):
            assert line.startswith(BUDGET_NOTE_PREFIXES), (
                f"{name}: mentions a RapidAPI tool outside the budget note: {line[:70]!r}"
            )


# blueteam_ip_intel_bulk is a threat-intel tool, never a reporting/local one.
@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_bulk_tool_is_never_in_the_threat_intel_row(name):
    rows = _rows(_read(name))
    for label in THREAT_INTEL_LABELS:
        assert "blueteam_ip_intel_bulk" not in rows.get(label, ""), (
            f"{name}: the metered bulk lookup is listed as an available threat-intel source"
        )


# Nothing metered is filed under reporting / local assembly
@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_reporting_row_names_no_metered_tool(name):
    rows = _rows(_read(name))
    assert REPORTING_LABELS & rows.keys(), f"{name}: no reporting row found"
    reporting = next(rows[k] for k in REPORTING_LABELS if k in rows)
    offenders = [t for t in RAPIDAPI_TOOLS if t in reporting]
    assert not offenders, f"{name}: RapidAPI tools under reporting: {offenders}"

    local = rows["Pelaporan & intelijen" if "Pelaporan & intelijen" in rows
                 else "Reporting & intelligence"]
    assert "`blueteam_extract_iocs`" in local and "`blueteam_ioc_lifecycle`" in local, (
        f"{name}: the local IOC store tools must stay listed under reporting"
    )


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_budget_note_states_the_closed_pool(name):
    """The account limit is shared and closed by default, which is the whole reason a
    report may not call these tools. A note that drifts on the number is worse than no
    note: the LLM would reason about a budget the server does not have."""
    notes = [n for n in _notes(_read(name)) if n.startswith(BUDGET_NOTE_PREFIXES)]
    assert len(notes) == 1, f"{name}: expected exactly one RapidAPI budget note, got {len(notes)}"
    note = notes[0]
    assert "0 of 100" in note or "0 dari 100" in note, (
        f"{name}: budget note lost the armed/account-wide pair (0 armed, 100 shared)"
    )
    assert "Budget closed" in note, (
        f"{name}: budget note no longer quotes the refusal the guard returns, so the LLM "
        "cannot connect the error it sees to this instruction"
    )
    for tool in RAPIDAPI_TOOLS:
        assert f"`{tool}`" in note, f"{name}: budget note does not name {tool}"
    for tool in QUOTA_FREE_TOOLS:
        assert f"`{tool}`" in note, f"{name}: budget note does not offer {tool} as the substitute"


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_reconciliation_rule_present(name):
    """The aggregate excludes RapidAPI and the RapidAPI tools refuse a scheduled run,
    so the rule has to name the sources the verdict actually comes from."""
    text = _read(name)
    rules = _rules(text)
    assert rules, f"{name}: no numbered Rules section found"
    matches = [body for _, body in rules
               if "blueteam_threat_intel_aggregate" in body and "tor" in body]
    assert len(matches) == 1, f"{name}: expected one reconciliation rule, got {len(matches)}"
    assert "crowdsec_ip_reputation" in matches[0], (
        f"{name}: reconciliation rule lost the quota-free substitutes"
    )


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_rules_are_contiguously_numbered(name):
    """Catches a botched renumber after inserting the reconciliation rule."""
    rules = _rules(_read(name))
    assert [n for n, _ in rules] == list(range(1, len(rules) + 1)), \
        f"{name}: rules numbered {[n for n, _ in rules]}"
    last = rules[-1][1]
    assert "Tulis dalam Bahasa Indonesia." in last or "Write in English." in last, (
        f"{name}: the language rule must stay last, found: {last[:60]}"
    )
    assert len(rules) == 7, f"{name}: expected 7 rules, got {len(rules)}"


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_tables_and_notes_are_well_formed(name):
    lines = _read(name).splitlines()

    block: list[str] = []
    for line in lines + [""]:
        if line.startswith("|"):
            block.append(line)
            continue
        if block:
            widths = {l.count("|") for l in block}
            assert len(widths) == 1, f"{name}: ragged table, pipe counts {widths} in:\n" + "\n".join(
                l[:80] for l in block
            )
            block = []

    for note in _notes("\n".join(lines)):
        assert note.count("`") % 2 == 0, f"{name}: unbalanced inline code in note: {note[:80]}"
        assert len(note) > 40, f"{name}: stub note left behind: {note!r}"


RERANK_FIELD_MODELS = {
    "blueteam_prompt_route": ("mcp_server.tools.prompt_router", "PromptRouteInput"),
    "blueteam_semantic_search": ("mcp_server.tools.semantic_search", "SemanticSearchInput"),
    "blueteam_rag_query": ("mcp_server.tools.rag_kb", "RagQueryInput"),
    "blueteam_rag_fp_validate": ("mcp_server.tools.rag_kb", "RagFpValidateInput"),
}

_ON_DEFAULT = "on by default"
_OFF_DEFAULT = "off by default"


def _declared_rerank_defaults() -> dict[str, bool]:
    """tool name -> its Pydantic ``rerank`` field default, the code's own answer."""
    import importlib
    defaults: dict[str, bool] = {}
    for tool, (module_name, model_name) in RERANK_FIELD_MODELS.items():
        model = getattr(importlib.import_module(module_name), model_name)
        defaults[tool] = bool(model.model_fields["rerank"].default)
    return defaults


def test_rerank_default_claims_match_the_pydantic_field():
    """Every taxonomy row that states a rerank default must match the field default.
    Only rows asserting "on by default" / "off by default" are read, so unrelated rows
    (a tool that is "read-only by default", say) are ignored rather than mis-parsed.
    """
    defaults = _declared_rerank_defaults()
    claims: list[tuple[str, str]] = []
    for line in SKILL_PATH.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        if _ON_DEFAULT not in line and _OFF_DEFAULT not in line:
            continue
        match = re.search(r"blueteam_[a-z_]+", line)
        assert match, f"rerank default claimed in a row that names no tool: {line[:90]}"
        claims.append((match.group(0), line))

    assert claims, (
        "no 'on by default' / 'off by default' row found in soc-analysis.md. If the wording "
        "changed, update this test: it is silently checking nothing otherwise."
    )
    for tool, line in claims:
        assert tool in defaults, (
            f"soc-analysis.md claims a rerank default for {tool}, which exposes no rerank "
            f"field. Row: {line[:90]}"
        )
        expected = _ON_DEFAULT if defaults[tool] else _OFF_DEFAULT
        assert expected in line, (
            f"{tool}.rerank defaults to {defaults[tool]}, so its taxonomy row must say "
            f"'{expected}'. Fix resource/skill/soc-analysis.md (README's copy is generated "
            f"from it, never hand-edited). Row: {line[:140]}"
        )
