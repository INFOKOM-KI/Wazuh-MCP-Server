#!/usr/bin/env python3
"""Consent tokens may only be minted behind host elicitation, or by the CLI.

``lookup()`` always calls ``consume_consent()``, so no request can be made without
a token. The remaining hole is token *issuance*: ``issue_consent()`` is an ordinary
function, and a future MCP tool could call it directly to "make lookups work",
skipping the prompt entirely.

This module enforces the policy at the source level with ``ast``, which does not
care how a name is spelled after import (``from x import issue_consent as mint``,
``import x as v; v.issue_consent(...)``), and at runtime for the token contract.
No network access, no live provider call.
"""
from __future__ import annotations

import ast
import os
import pathlib

import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

REPO = pathlib.Path(__file__).resolve().parent.parent
TOOLS = REPO / "mcp_server" / "tools"
PKG = REPO / "mcp_server"

# The one place outside mcp_server/tools/ that may mint a token: the operator CLI.
CLI_MODULE = PKG / "threat_intel" / "virustotal_live.py"
# Issuance plumbing, not a call site.
PLUMBING = {
    PKG / "threat_intel" / "virustotal_consent.py",
    PKG / "threat_intel" / "virustotal.py",
}

ELICIT = "request_ioc_sharing"
# The detailed form is the same gate; it returns the refusal reason alongside.
ELICIT_NAMES = {ELICIT, "request_ioc_sharing_detailed"}
MINT = "issue_consent"


def _aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Return (mint names, elicit names) as they appear in this module."""
    mint = {MINT}
    elicit = set(ELICIT_NAMES)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == MINT:
                mint.add(local)
            elif alias.name in ELICIT_NAMES:
                elicit.add(local)
    return mint, elicit


def _is_call_to(node: ast.AST, names: set[str], attr_name: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in names
    if isinstance(func, ast.Attribute):
        # v.issue_consent(...) and module.issue_consent(...)
        return func.attr == attr_name or func.attr in ELICIT_NAMES
    return False


def _function_chain(tree: ast.Module) -> dict[int, ast.AST]:
    """Map id(call) -> the OUTERMOST enclosing function of that call.

    Outermost, not innermost: the curated report elicits once in the tool body and
    then mints per IP inside a nested helper, so the gate lives one level up.
    """
    owner: dict[int, ast.AST] = {}

    def visit(node: ast.AST, outer: ast.AST | None) -> None:
        for child in ast.iter_child_nodes(node):
            child_outer = outer
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_outer = outer or child
            if isinstance(child, ast.Call) and child_outer is not None:
                owner[id(child)] = child_outer
            visit(child, child_outer)

    visit(tree, None)
    return owner


def _calls_within(func: ast.AST, tree: ast.Module, name: str) -> bool:
    mint_names, elicit_names = _aliases(tree)
    return any(_is_call_to(node, elicit_names, ELICIT)
               for node in ast.walk(func))


def _mint_sites(tree: ast.Module) -> list[ast.Call]:
    mint_names, _ = _aliases(tree)
    return [node for node in ast.walk(tree)
            if _is_call_to(node, mint_names, MINT)]


def audit_source(text: str, *, path: pathlib.Path, allow_mint: bool) -> list[str]:
    """Return one problem string per ungated token mint. Empty means compliant."""
    tree = ast.parse(text)
    problems: list[str] = []
    owners = _function_chain(tree)
    for call in _mint_sites(tree):
        if allow_mint:
            continue
        owner = owners.get(id(call))
        if owner is None:
            problems.append(f"{path.name}:{call.lineno} mints a token at module "
                            f"scope, outside any elicitation gate")
            continue
        if not _calls_within(owner, tree, ELICIT):
            problems.append(
                f"{path.name}:{call.lineno} mints a token in "
                f"{getattr(owner, 'name', '?')}() with no {ELICIT}() call in that "
                f"function or an enclosing one")
    return problems


def _tool_modules() -> list[pathlib.Path]:
    return sorted(TOOLS.glob("*.py"))


def test_every_mcp_tool_mint_is_behind_host_elicitation():
    problems: list[str] = []
    for path in _tool_modules():
        problems.extend(audit_source(path.read_text(encoding="utf-8"),
                                     path=path, allow_mint=False))
    assert not problems, (
        "an MCP tool mints a VirusTotal consent token without host elicitation:\n  "
        + "\n  ".join(problems))


def test_mint_sites_outside_tools_are_only_the_operator_cli():
    offenders: list[str] = []
    for path in sorted(PKG.rglob("*.py")):
        if "__pycache__" in str(path) or path.is_relative_to(TOOLS):
            continue
        if path in PLUMBING:
            continue
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for call in _mint_sites(tree):
            if path != CLI_MODULE:
                offenders.append(f"{path.relative_to(REPO)}:{call.lineno}")
    assert not offenders, (
        "consent tokens are minted outside mcp_server/tools/ and outside the "
        f"operator CLI: {offenders}")


def test_the_operator_cli_is_the_one_exempt_module():
    assert CLI_MODULE.is_file()
    problems = audit_source(CLI_MODULE.read_text(encoding="utf-8"),
                            path=CLI_MODULE, allow_mint=False)
    # The CLI mints directly; the audit above only passes because it is exempt.
    assert problems, "the CLI is expected to mint without elicitation"


def test_lookup_consumes_a_token_on_every_path():
    source = (PKG / "threat_intel" / "virustotal.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    consume = [n for n in ast.walk(tree)
               if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Name) and n.func.id == "consume_consent"]
    assert len(consume) == 1, "lookup() must consume exactly one token per call"


def test_no_tool_module_imports_consent_plumbing_directly_by_relay():
    """A tool may not re-export a mint function for another module to use."""
    offenders = []
    for path in _tool_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == MINT and alias.asname:
                        offenders.append(f"{path.name} aliases {MINT}")
    assert not offenders, offenders


# The checker itself must not be vacuous

def test_checker_flags_a_direct_mint(tmp_path):
    path = tmp_path / "bad_tool.py"
    problems = audit_source(
        "from mcp_server.threat_intel.virustotal import issue_consent\n"
        "async def lookup_it(ip):\n"
        "    return issue_consent('ip_addresses', ip)\n",
        path=path, allow_mint=False)
    assert problems and "no request_ioc_sharing" in problems[0]


def test_checker_flags_an_aliased_module_mint(tmp_path):
    path = tmp_path / "bad_tool2.py"
    problems = audit_source(
        "import mcp_server.threat_intel.virustotal_consent as vc\n"
        "async def lookup_it(ip):\n"
        "    return vc.issue_consent('ip_addresses', ip)\n",
        path=path, allow_mint=False)
    assert problems


def test_checker_accepts_an_elicited_mint(tmp_path):
    path = tmp_path / "good_tool.py"
    problems = audit_source(
        "from mcp_server.threat_intel.virustotal import issue_consent\n"
        "from mcp_server.threat_intel.virustotal_consent import request_ioc_sharing\n"
        "async def lookup_it(ctx, ip):\n"
        "    if not await request_ioc_sharing(ctx, 'msg'):\n"
        "        return None\n"
        "    return issue_consent('ip_addresses', ip)\n",
        path=path, allow_mint=False)
    assert problems == []


def test_checker_accepts_a_nested_mint_under_an_eliciting_outer_function(tmp_path):
    """The curated report elicits once, then its inner helper mints per IP."""
    path = tmp_path / "nested_tool.py"
    problems = audit_source(
        "from mcp_server.threat_intel.virustotal import issue_consent\n"
        "from mcp_server.threat_intel.virustotal_consent import request_ioc_sharing\n"
        "async def report(ctx, ips):\n"
        "    approved = set()\n"
        "    if await request_ioc_sharing(ctx, 'msg'):\n"
        "        approved = set(ips)\n"
        "    async def enrich(ip):\n"
        "        if ip not in approved:\n"
        "            return None\n"
        "        return issue_consent('ip_addresses', ip)\n"
        "    return [await enrich(i) for i in ips]\n",
        path=path, allow_mint=False)
    assert problems == []
