#!/usr/bin/env python3
"""
Drift guard for the 12 SOC report prompts in resource/your_prompthings/.
These are static files, not generated. When the tool set, the RapidAPI caching, or
the metered-vs-local split changes, the prompts go stale silently and the LLM keeps
calling a quota-metered API as if it were a local lookup.
Each test encodes one property that was wrong on 2026-09-14 and has no other
enforcement. Run: pytest tests/test_prompt_drift.py -q
"""
from __future__ import annotations
import pathlib
import re
import pytest

PROMPT_DIR = pathlib.Path(__file__).resolve().parent.parent / "resource" / "your_prompthings"

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

# The RapidAPI tools that remain in prompt guidance: separate subscriptions,
# separate quotas, both metered. `blueteam_ip_blacklist` was deliberately removed
# from the prompts (a third paid product the SOC workflow does not need); the
# absence assertion below keeps it removed.
METERED_TOOLS = ("blueteam_ioc_search", "blueteam_breach_check")
DEPRECATED_TOOLS = ("blueteam_ip_blacklist",)
METERED_MARKER = re.compile(r"`(?P<tool>[a-z_]+)` \(metered, RapidAPI\)")

THREAT_INTEL_LABELS = {"Intel ancaman", "Threat intel"}
REPORTING_LABELS = {"Pelaporan & intelijen", "Reporting & intelligence"}
QUOTA_NOTE_PREFIXES = ("> RapidAPI quota:", "> Kuota RapidAPI:")


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
def test_all_twelve_prompt_files_exist():
    missing = [f for f in EXPECTED_FILES if not (PROMPT_DIR / f).is_file()]
    assert not missing, f"prompt files missing from {PROMPT_DIR}: {missing}"
    found = {p.name for p in PROMPT_DIR.glob("*.md")}
    assert found == set(EXPECTED_FILES), f"unexpected prompt files: {found - set(EXPECTED_FILES)}"


# Every metered RapidAPI tool is marked, and nothing else is.
@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_metered_marker_exactly_on_the_rapidapi_tools(name):
    """A metered tool without the marker reads as free, which is the original bug."""
    marked = set(METERED_MARKER.findall(_read(name)))
    assert marked == set(METERED_TOOLS), f"{name}: marked={sorted(marked)}"


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_deprecated_tools_stay_out_of_the_prompts(name):
    """blueteam_ip_blacklist is a separate paid RapidAPI product. It stays
    registered on the server but must not be advertised to the LLM, or every run
    re-attempts an unsubscribed call. Removing the table row alone is not enough:
    blueteam_prompt_route and blueteam_semantic_search can surface an unlisted
    tool, so the quota note carries an explicit 'do not call' line."""
    text = _read(name)
    rows = _rows(text)
    for tool in DEPRECATED_TOOLS:
        holders = [label for label, line in rows.items() if f"`{tool}`" in line]
        assert not holders, f"{name}: {tool} back in the tool table under {holders}"
    note_keywords = ("Do not call", "Jangan panggil")
    assert any(k in text for k in note_keywords), (
        f"{name}: the explicit 'do not call {DEPRECATED_TOOLS[0]}' line is gone"
    )


# blueteam_ioc_search is a threat-intel tool, never a reporting/local one.
@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_ioc_search_appears_only_in_the_threat_intel_row(name):
    rows = _rows(_read(name))
    holders = [label for label, line in rows.items() if "`blueteam_ioc_search`" in line]
    assert holders == ["Intel ancaman"] or holders == ["Threat intel"], (
        f"{name}: `blueteam_ioc_search` listed under {holders}. It is a metered "
        "RapidAPI call, not a local IOC store query."
    )


# Nothing metered is filed under reporting / local assembly
@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_reporting_row_names_no_metered_tool(name):
    rows = _rows(_read(name))
    assert REPORTING_LABELS & rows.keys(), f"{name}: no reporting row found"
    reporting = next(rows[k] for k in REPORTING_LABELS if k in rows)
    offenders = [t for t in METERED_TOOLS if t in reporting]
    assert not offenders, f"{name}: metered tools under reporting: {offenders}"

    local = rows["Pelaporan & intelijen" if "Pelaporan & intelijen" in rows
                 else "Reporting & intelligence"]
    assert "`blueteam_extract_iocs`" in local and "`blueteam_ioc_lifecycle`" in local, (
        f"{name}: the local IOC store tools must stay listed under reporting"
    )


# The quota note survives, and still says the things that matter.
@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_quota_note_present_and_complete(name):
    text = _read(name)
    notes = [n for n in _notes(text) if n.startswith(QUOTA_NOTE_PREFIXES)]
    assert len(notes) == 1, f"{name}: expected exactly one RapidAPI quota note, got {len(notes)}"
    note = notes[0]
    for tool in METERED_TOOLS:
        assert f"`{tool}`" in note, f"{name}: quota note does not name {tool}"
    assert "403" in note and "429" in note, f"{name}: quota note lost the 403/429 guidance"
    assert "cached" in note or "di-cache" in note, f"{name}: quota note lost the cache horizon"
    assert "threatfox_ioc_search" in note, (
        f"{name}: quota note must keep `blueteam_ioc_search` distinct from "
        "`threatfox_ioc_search`; they share a name pattern and only one is metered"
    )


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_verdict_framing_note_present(name):
    """detail_level is the difference between a 3-line triage answer and a 70 KB
    dump. If the prompt stops naming the levels, the LLM defaults to raw forever."""
    notes = [n for n in _notes(_read(name)) if "detail_level" in n]
    assert len(notes) == 1, f"{name}: expected one ioc_search framing note, got {len(notes)}"
    note = notes[0]
    assert "blueteam_ioc_search" in note, f"{name}: framing note does not name the tool"
    for level in ("detail_level=\"summary\"", "detail_level=\"forensic\"", "detail_level=\"raw\""):
        assert level in note, f"{name}: framing note lost {level}"


@pytest.mark.parametrize("name", EXPECTED_FILES)
def test_reconciliation_rule_present(name):
    """The aggregate excludes RapidAPI, so the two can contradict each other. The
    rule tells the LLM to report both instead of picking one."""
    text = _read(name)
    rules = _rules(text)
    assert rules, f"{name}: no numbered Rules section found"
    matches = [body for _, body in rules if "blueteam_ioc_search" in body and "aggregate" in body]
    assert len(matches) == 1, f"{name}: expected one reconciliation rule, got {len(matches)}"
    assert "tor" in matches[0], f"{name}: reconciliation rule lost the tor-tag guidance"


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


# 6-7. Markdown hygiene, so an edit cannot silently break the tables or notes.
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
