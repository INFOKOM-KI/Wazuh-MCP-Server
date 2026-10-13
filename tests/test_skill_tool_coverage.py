#!/usr/bin/env python3
"""Drift guard for the canonical tool taxonomy in resource/skill/soc-analysis.md.

That section is now the only place the full tool list lives. Nothing checked it
against the registry, and the twelve deleted prompt copies had drifted to 147 of 160
tools while the skill still named all 160, which is the failure these tests exist to
catch in the survivor.

Three requirements, across seven checks, each reporting tool and category names rather
than a count:

1. Every registered tool is named inside `## 1. Tool taxonomy`. Prose elsewhere in the
   document does not count, so the vocabulary of section 5 cannot satisfy coverage.
2. Every tool-shaped token inside that section resolves to a registered tool, so a
   renamed or removed tool leaves a visible stale reference.
3. Every registered tool has a table-row placement, every placement sits under a
   subsection its category declares, every registry category is declared in the map,
   no mapped category or subsection is stale, and the one prose-only exception is
   still required. A mention in a subsection's prose is a cross-reference, not a
   placement, so it cannot satisfy or violate the placement checks.

The 17 areas in resource/your_prompthings are a discovery aid for routing and have
different boundaries from these subsections, so nothing here maps one to the other.

The ten tests at the bottom are the negative controls: each one asserts a check fails
on a condition it exists to catch, so a guard that silently stopped biting is caught
here rather than in production.

Run: pytest tests/test_skill_tool_coverage.py -q
"""
from __future__ import annotations

import ast
import os
import pathlib
import re
import sys
import types

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.tools import register_all_tools
from mcp_server import mcp

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL_PATH = ROOT / "resource" / "skill" / "soc-analysis.md"
TOOLS_INIT = ROOT / "mcp_server" / "tools" / "__init__.py"

TAXONOMY_HEADING = "## 1. Tool taxonomy"
TAXONOMY_END = "\n## 2. "

# Prefixes that mark a backticked token as a possible tool name. A bare field name
# or response key carries none of them, so `rerank_engine`, `rule_id` and `srcip`
# never reach the resolver and need no entry below.
TOOL_SHAPED = re.compile(r"`(" + "|".join(
    f"{prefix}_[a-z0-9_]+" for prefix in (
        "blueteam", "wazuh", "sangfor", "three_sum", "crowdsec", "threatfox", "otx",
        "urlhaus", "greynoise", "argus", "netra", "jarm", "stealer", "misp", "cve",
        "abuseipdb", "virustotal",
    )) + r")")

# Backticked tokens inside the taxonomy that match TOOL_SHAPED and are not tools.
# Two entries, both deliberate. Anything added here needs a stated reason, because a
# growing list is how a stale reference hides.
NON_TOOL_IDENTIFIERS = {
    # A wildcard naming the STIX tool family: "If a `blueteam_stix_*` call ...".
    "blueteam_stix_",
    # A field name returned by blueteam_dependency_scan and fed to the blueteam_cve_* tools.
    "cve_ids",
}

# Modules register_all_tools() imports outside _MODULES, so they carry no gating
# category. It names six: crowdsec, greynoise, threatfox, otx, urlhaus, rapidapi. Only
# four of them register tools in this repository (otx and urlhaus define theirs under
# mcp_server/tools/), producing nine tools across four categories. A module attribute
# outside both _MODULES and this set is a failure, never an assumed provider.
PROVIDER_MODULES = frozenset({"crowdsec", "greynoise", "threatfox", "rapidapi"})

# Tools the taxonomy documents in a subsection's lead sentence instead of a table row.
# Keyed by tool name, valued by the subsection the prose belongs to. This is the
# narrow exception that lets check 3 keep treating prose mentions as cross-references
# everywhere else. One entry, and the test below fails if it stops being true.
PROSE_ONLY_PLACEMENTS = {
    # "`blueteam_curated_threat_report(filters={...})` is the single entry point for
    # filtered reports" opens the subsection; its table maps analyst phrases to filter
    # dicts, so the tool itself never appears in a row.
    "blueteam_curated_threat_report": "Filtered reporting",
}

# Which registry categories may be PLACED under which taxonomy subsection. Built from
# where each category's tools appear in table rows, so cross-references are not
# blessed here. Check 3 only, and the only maintained part of this file: a new tool in
# an existing category needs no edit, a new category or a moved tool does.
SECTION_CATEGORIES: dict[str, set[str]] = {
    "Triage": {
        "alert_attack_chain", "alert_beacon", "alert_compare", "alert_summarize",
        "alert_threat_card", "forensic_window", "stix_correlation", "wazuh_siem",
        "wazuh_timeline", "wazuh_velocity",
    },
    "Threat intel": {
        "alert_enrichment", "misp", "otx_lookup", "threat_intel_aggregate", "urlhaus",
        "provider_crowdsec", "provider_greynoise", "provider_rapidapi",
    },
    "CVE / vulnerability enrichment": {
        "cve_enrichment", "dependency_scan", "stix_correlation", "vendor_advisory",
    },
    "Correlation / APT detection": {
        "attack_graph", "baseline", "correlation", "investigation_history", "rag_kb",
        "stix_correlation",
    },
    "Alert clustering & incident labeling": {"cluster", "forecast", "label"},
    "Investigation / case management": {
        "case", "correlation", "investigation_history", "investigation_workflow", "rag_kb",
    },
    "Local case RAG": {"rag_kb"},
    "Investigation memory": {"memory"},
    "Email / breach / domain forensics": {
        "domain_permute", "stealer_log", "wazuh_compromised", "wazuh_domain",
        "wazuh_email", "provider_rapidapi",
    },
    "Filtered reporting": {"alert_curated_report"},
    "Geo / scanning / host forensics": {
        "document_convert", "fail2ban", "geo", "host_forensics", "wazuh_scanning",
        "webshell_check",
    },
    "Extended toolbox": {
        "ai_bot_recon", "alert_enrichment", "asset_context", "baseline", "cluster",
        "correlation", "dsl_query", "forecast", "index_schema", "investigation_history",
        "ioc_tools", "jarm", "label", "metrics", "otx_lookup", "owned_domains",
        "playbook_runner", "prompt_router", "report_export", "semantic_search",
        "sigma_rules", "stix_export", "subnetting", "threat_hunt", "urlhaus",
        "wazuh_export", "wazuh_focused", "wazuh_manager", "wazuh_rules_files",
        "wazuh_sca", "wazuh_siem", "yara_rules",
        "provider_crowdsec", "provider_rapidapi", "provider_threatfox",
    },
}

# Tool gating shrinks the registry, which would turn every check below into a smaller
# question than it claims to answer. Refuse instead of reporting a hollow pass.
GATING_ENV = ("WAZUH_DISABLED_TOOLS", "WAZUH_DISABLED_CATEGORIES", "WAZUH_READ_ONLY")


def _module_categories() -> dict[str, str]:
    """Module attribute to gating category, read from tools/__init__.py.

    `_MODULES` is a local inside register_all_tools(), so it is parsed out of the
    source rather than imported. That is the same metadata the gating loop reads.
    """
    source = TOOLS_INIT.read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "_MODULES":
            return {attr: category for attr, category, _ in ast.literal_eval(node.value)}
    raise AssertionError(
        f"no _MODULES assignment found in {TOOLS_INIT}; the gating metadata moved, so "
        "category assignment can no longer be derived"
    )


MODULE_CATEGORY = _module_categories()


def _categories(registry: dict[str, object]) -> dict[str, str]:
    """Tool name to category, failing closed on any module neither gated nor declared.

    A module outside _MODULES is only treated as a provider when it is named in
    PROVIDER_MODULES. Anything else raises with the module attribute and every tool it
    registered, because silently inventing a category is how a real drift hides.
    """
    resolved: dict[str, str] = {}
    unknown: dict[str, list[str]] = {}
    for name, tool in registry.items():
        attribute = getattr(getattr(tool, "fn", None), "__module__", "").rsplit(".", 1)[-1]
        if attribute in MODULE_CATEGORY:
            resolved[name] = MODULE_CATEGORY[attribute]
        elif attribute in PROVIDER_MODULES:
            resolved[name] = f"provider_{attribute}"
        else:
            unknown.setdefault(attribute, []).append(name)
    assert not unknown, (
        "tool(s) registered from a module that is neither in _MODULES nor in "
        f"PROVIDER_MODULES (module attribute: tools): {unknown}. Add the module to one "
        "of them, or the category cannot be derived and check 3 means nothing."
    )
    return resolved


def _mentions(body: str, name: str) -> bool:
    """True when `body` names this tool, either bare or with a parameter list.

    A plain substring test is not enough: seven registered names are a prefix of
    another registered name (`blueteam_ioc_search` against
    `blueteam_ioc_search_bulk`), so `` `blueteam_ioc_search `` matches inside the bulk
    tool's mention and the shorter tool would pass while undocumented. The lookahead
    requires the name to end where a reference ends.
    """
    return re.search(rf"`{re.escape(name)}(?=[`(])", body) is not None


def _taxonomy_sections() -> dict[str, str]:
    """Subsection name to body for `## 1. Tool taxonomy`, plus "" for its intro.

    The name drops any trailing parenthetical, so `Local case RAG (opt-in, needs ...)`
    and `Local case RAG` are the same key and an opt-in requirement can change without
    invalidating the map.
    """
    text = SKILL_PATH.read_text(encoding="utf-8")
    start = text.index(TAXONOMY_HEADING)
    parts = re.split(r"(?m)^### (.*)$", text[start:text.index(TAXONOMY_END, start)])
    sections = {"": parts[0]}
    for index in range(1, len(parts), 2):
        sections[parts[index].split(" (")[0].strip()] = parts[index + 1]
    return sections


def _placements(sections: dict[str, str], name: str) -> list[str]:
    """Subsections that place this tool in a table row, which is what a placement is.

    A mention in a subsection's prose does not count. Without that split, a
    cross-reference reads as a category assignment and a tool moved to a wrong
    subsection still passes on the strength of the right one.
    """
    found = []
    for heading, body in sections.items():
        if not heading:
            continue
        rows = "\n".join(line for line in body.splitlines() if line.startswith("|"))
        if _mentions(rows, name):
            found.append(heading)
    return sorted(found)


def _unplaced(sections: dict[str, str], categories: dict[str, str]) -> list[str]:
    """Tools with no table-row placement and no declared prose-only exception."""
    return sorted(name for name in categories
                  if not _placements(sections, name)
                  and name not in PROSE_ONLY_PLACEMENTS)


def _stale_prose_exceptions(sections: dict[str, str]) -> dict[str, str]:
    """Prose-only tools that have gained a table-row placement in any subsection.

    The exception exempts a tool from needing a placement. It stops being valid the
    moment the tool appears in any table row, because then the row is the placement and
    the exception is a blind spot that hides it from the placement checks.
    """
    return {name: ", ".join(_placements(sections, name))
            for name in PROSE_ONLY_PLACEMENTS if _placements(sections, name)}


def _misplaced(sections: dict[str, str], categories: dict[str, str],
               mapping: dict[str, set[str]] | None = None) -> dict[str, list[str]]:
    """Tool to the subsections it is placed in that its category does not declare.

    Every placement is checked, not the first matching one, and no tool is skipped. A
    tool sitting in both a permitted and an unpermitted subsection is a real defect,
    and an `any()` test over its placements would hide it. A prose-only tool has no
    placement while its exception holds, so it appears here the moment it gains one.
    """
    mapping = SECTION_CATEGORIES if mapping is None else mapping
    out: dict[str, list[str]] = {}
    for name, category in categories.items():
        bad = [heading for heading in _placements(sections, name)
               if category not in mapping.get(heading, set())]
        if bad:
            out[name] = bad
    return out


def _fake_tool(module: str) -> types.SimpleNamespace:
    """Stand-in for a FastMCP Tool. Only `fn.__module__` is read by _categories()."""
    return types.SimpleNamespace(fn=types.SimpleNamespace(__module__=module))


@pytest.fixture(scope="module")
def registry() -> dict[str, object]:
    gated = [name for name in GATING_ENV if os.environ.get(name)]
    assert not gated, (
        f"{gated} is set, so the registry is gated and these checks would cover fewer "
        "tools than they report"
    )
    register_all_tools()
    # tests/test_tool_decorator.py registers throwaway tools into the same FastMCP
    # registry, and module imports are cached, so they stay registered for every test
    # module that runs after it. The taxonomy documents server tools, so scope to
    # those. Without this, the guard fails naming blueteam_test_* fixtures.
    return {tool.name: tool for tool in mcp._tool_manager.list_tools()
            if getattr(tool.fn, "__module__", "").startswith("mcp_server.")}


def test_every_registered_tool_is_named_in_the_taxonomy(registry):
    body = "\n".join(_taxonomy_sections().values())
    missing = sorted(name for name in registry if not _mentions(body, name))
    assert not missing, (
        f"{len(missing)} registered tool(s) absent from `{TAXONOMY_HEADING}`: {missing}. "
        "Name each one in the subsection that matches its category."
    )


def test_no_stale_tool_references_in_the_taxonomy(registry):
    body = "\n".join(_taxonomy_sections().values())
    stale = sorted({match.group(1) for match in TOOL_SHAPED.finditer(body)}
                   - set(registry) - NON_TOOL_IDENTIFIERS)
    assert not stale, (
        f"{len(stale)} tool-shaped reference(s) inside `{TAXONOMY_HEADING}` do not "
        f"resolve to a registered tool: {stale}. Either the tool was renamed or "
        "removed, or the token is a non-tool identifier that belongs in "
        "NON_TOOL_IDENTIFIERS with a stated reason."
    )


def test_every_registry_category_is_declared_in_the_section_map(registry):
    declared = {category for categories in SECTION_CATEGORIES.values()
                for category in categories}
    undeclared = sorted(set(_categories(registry).values()) - declared)
    assert not undeclared, (
        f"{len(undeclared)} registry category(ies) missing from SECTION_CATEGORIES: "
        f"{undeclared}. Add each one to every subsection that places its tools."
    )


def test_no_stale_category_or_section_in_the_map(registry):
    declared = {category for categories in SECTION_CATEGORIES.values()
                for category in categories}
    retired = sorted(declared - set(_categories(registry).values()))
    assert not retired, (
        f"SECTION_CATEGORIES declares {len(retired)} category(ies) no tool uses: "
        f"{retired}. Remove them, or fix the module attribute they were derived from."
    )

    renamed = sorted(set(SECTION_CATEGORIES) - set(_taxonomy_sections()))
    assert not renamed, (
        f"SECTION_CATEGORIES keys {renamed} are not subsections of `{TAXONOMY_HEADING}`. "
        "A heading was renamed or removed."
    )


def test_every_tool_has_a_placement(registry):
    unplaced = _unplaced(_taxonomy_sections(), _categories(registry))
    assert not unplaced, (
        f"{len(unplaced)} registered tool(s) have no table-row placement in "
        f"`{TAXONOMY_HEADING}`: {unplaced}. A prose mention is a cross-reference, so "
        "either add the tool to the subsection table that owns its category, or add it "
        "to PROSE_ONLY_PLACEMENTS with the subsection it opens."
    )


def test_every_placement_matches_the_tools_category(registry):
    misplaced = _misplaced(_taxonomy_sections(), _categories(registry))
    assert not misplaced, (
        "tool(s) placed under a subsection their category does not declare "
        f"(tool: subsections): {misplaced}"
    )


def test_prose_only_placement_exception_is_still_required(registry):
    """A stale exception is a blind spot, so it has to prove it is still one.

    The named tool must be registered, its subsection must exist and declare its
    category, and it must have no table row anywhere in the taxonomy. The last check
    covers every subsection, not only the one the exception names.
    """
    assert PROSE_ONLY_PLACEMENTS, "the exception was removed; delete this test with it"
    categories = _categories(registry)
    sections = _taxonomy_sections()

    stale = _stale_prose_exceptions(sections)
    assert not stale, (
        f"PROSE_ONLY_PLACEMENTS exempts tool(s) that now have a table-row placement: "
        f"{stale}. Drop the exception and let the placement checks apply."
    )

    for name, heading in PROSE_ONLY_PLACEMENTS.items():
        assert name in registry, f"{name} is no longer registered; drop its exception"
        assert heading in sections, (
            f"{name}: subsection {heading!r} no longer exists in `{TAXONOMY_HEADING}`"
        )
        assert categories[name] in SECTION_CATEGORIES.get(heading, set()), (
            f"{name} is a {categories[name]} tool but SECTION_CATEGORIES[{heading!r}] "
            "does not declare that category"
        )


# Negative controls. Each drives a real check with a synthetic input and asserts it
# fails, so a guard that stopped biting fails here instead of passing quietly.


def test_guard_catches_a_tool_missing_from_the_taxonomy(registry):
    synthetic = {**registry,
                 "blueteam_ghost_tool": _fake_tool("mcp_server.tools.host_forensics")}
    with pytest.raises(AssertionError, match="blueteam_ghost_tool"):
        test_every_registered_tool_is_named_in_the_taxonomy(synthetic)


def test_guard_catches_a_stale_reference_to_a_removed_tool(registry):
    synthetic = {name: tool for name, tool in registry.items()
                 if name != "blueteam_stix_killchain"}
    with pytest.raises(AssertionError, match="blueteam_stix_killchain"):
        test_no_stale_tool_references_in_the_taxonomy(synthetic)


def test_coverage_rejects_a_longer_tool_names_mention():
    """The prefix-collision hole: seven names are a prefix of another name."""
    body = "| Threat intel | `threatfox_ioc_search_bulk(ips=[...])` |"
    assert not _mentions(body, "threatfox_ioc_search")
    assert _mentions(body, "threatfox_ioc_search_bulk")


def test_guard_catches_a_category_missing_from_the_section_map(registry, monkeypatch):
    stripped = {heading: categories - {"metrics"}
                for heading, categories in SECTION_CATEGORIES.items()}
    monkeypatch.setattr(sys.modules[__name__], "SECTION_CATEGORIES", stripped)
    with pytest.raises(AssertionError, match="metrics"):
        test_every_registry_category_is_declared_in_the_section_map(registry)


def test_guard_catches_a_retired_category_in_the_section_map(registry, monkeypatch):
    stale = {heading: categories | {"ghost_category"}
             for heading, categories in SECTION_CATEGORIES.items()}
    monkeypatch.setattr(sys.modules[__name__], "SECTION_CATEGORIES", stale)
    with pytest.raises(AssertionError, match="ghost_category"):
        test_no_stale_category_or_section_in_the_map(registry)


def test_guard_fails_closed_on_an_undeclared_module(registry):
    synthetic = {**registry,
                 "blueteam_ghost_tool": _fake_tool("mcp_server.tools.brand_new_module")}
    with pytest.raises(AssertionError, match="brand_new_module"):
        _categories(synthetic)


def test_guard_catches_a_prose_mention_used_as_a_placement():
    """A cross-reference must not satisfy check 3 in either direction."""
    sections = {"Triage": "See `blueteam_check_webshell` for the host scan.\n"
                           "| Want | Tool |\n|---|---|\n| Card | `blueteam_threat_card` |",
                "Geo / scanning / host forensics":
                    "| Want | Tool |\n|---|---|\n| Webshell | `blueteam_check_webshell` |",
                }
    assert _placements(sections, "blueteam_check_webshell") == [
        "Geo / scanning / host forensics"]
    assert _misplaced(sections, {"blueteam_check_webshell": "webshell_check"}) == {}


def test_guard_catches_an_invalid_placement_beside_a_valid_one():
    """The defect an any() check over placements would hide."""
    sections = {
        "Triage": "| Want | Tool |\n|---|---|\n| Scan | `blueteam_check_webshell` |",
        "Geo / scanning / host forensics":
            "| Want | Tool |\n|---|---|\n| Webshell | `blueteam_check_webshell` |",
    }
    assert _misplaced(sections, {"blueteam_check_webshell": "webshell_check"}) == {
        "blueteam_check_webshell": ["Triage"]}


def test_guard_catches_a_tool_placed_only_under_an_incompatible_subsection():
    sections = {"Triage": "| Want | Tool |\n|---|---|\n| Scan | `blueteam_check_webshell` |"}
    misplaced = _misplaced(sections, {"blueteam_check_webshell": "webshell_check"})
    assert misplaced == {"blueteam_check_webshell": ["Triage"]}


def test_guard_rejects_a_prose_only_tool_that_gained_a_placement():
    """A row invalidates the exception, and the row is validated like any other."""
    sections = {
        "Filtered reporting": "`blueteam_curated_threat_report(filters={...})` opens this.",
        "Triage": "| Want | Tool |\n|---|---|\n| Report | `blueteam_curated_threat_report` |",
    }
    assert _stale_prose_exceptions(sections) == {"blueteam_curated_threat_report": "Triage"}
    assert _misplaced(sections, {"blueteam_curated_threat_report": "alert_curated_report"}) == {
        "blueteam_curated_threat_report": ["Triage"]}
