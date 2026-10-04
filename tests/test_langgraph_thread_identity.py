#!/usr/bin/env python3
"""Phase 0 thread identity for the three LangGraph workflows.

BLUETEAM_LANGGRAPH_DB unset changes nothing: thread ids stay random and no state is
read back. Set, the thread is keyed on the subject, a repeat run reports its earlier
runs, and the previous run's step log never appears in the new run's summary.
Durable tests skip without langgraph-checkpoint-sqlite and aiosqlite.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import importlib.util
import pathlib
from operator import add
from typing import Annotated, TypedDict
import pytest
from mcp_server.agents import fp_validator_graph as fpv
from mcp_server.agents import investigation_graph as ig
from mcp_server.agents import playbook_graph as pg
from mcp_server.core import attacker_registry, false_positive_kb
from mcp_server.core.config import config

_DURABLE_DEPS = all(importlib.util.find_spec(mod) is not None for mod in (
    "aiosqlite", "langgraph.checkpoint.sqlite"))
durable = pytest.mark.skipif(
    not _DURABLE_DEPS, reason="needs langgraph-checkpoint-sqlite + aiosqlite")


@pytest.fixture(autouse=True)
def _reset_state():
    config.rag.enabled = False
    config.rag.db_path = ""
    false_positive_kb.clear_false_positive_kb()
    attacker_registry.clear_attacker_registry()
    yield
    false_positive_kb.clear_false_positive_kb()
    attacker_registry.clear_attacker_registry()


async def _stored_steps(db_path: str, thread_id: str) -> list[str]:
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    ig._ensure_aiosqlite_is_alive()
    async with AsyncSqliteSaver.from_conn_string(db_path) as cp:
        graph = ig.build_investigation_graph(cp)
        snap = await graph.aget_state({"configurable": {"thread_id": thread_id}})
    return list((snap.values or {}).get("steps") or [])


async def _legacy_node(state):
    return {"steps": ["legacy step"]}


class _LegacyState(TypedDict, total=False):
    """Pre-Phase-0 schema: operator.add log, no run counter."""
    steps: Annotated[list[str], add]
    errors: Annotated[list[str], add]


async def _write_legacy_checkpoint(db_path: str, thread_id: str) -> None:
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    from langgraph.graph import END, START, StateGraph
    ig._ensure_aiosqlite_is_alive()

    graph = StateGraph(_LegacyState)
    graph.add_node("legacy", _legacy_node)
    graph.add_edge(START, "legacy")
    graph.add_edge("legacy", END)
    async with AsyncSqliteSaver.from_conn_string(db_path) as cp:
        await graph.compile(checkpointer=cp).ainvoke(
            {"steps": [], "errors": []},
            config={"configurable": {"thread_id": thread_id}})


def test_capped_add_keeps_the_tail():
    log = ig._capped_add([f"s{i}" for i in range(ig._STEP_LOG_CAP)], ["new"])
    assert len(log) == ig._STEP_LOG_CAP
    assert log[-1] == "new"
    assert log[0] == "s1"


def test_this_run_cuts_at_the_last_marker():
    assert ig._this_run([ig._RUN_MARKER, "a", ig._RUN_MARKER, "b"]) == ["b"]
    assert ig._this_run(["a", "b"]) == ["a", "b"]


def test_all_three_graphs_share_one_thread_helper():
    assert pg.thread_id_for is ig.thread_id_for
    assert fpv.thread_id_for is ig.thread_id_for


def test_setup_sh_does_not_enable_continuity_by_default():
    """An install must not start writing checkpoints until an admin asks for it.
    In pytest rather than check_setup_sh.sh because only pytest is a merge gate.
    """
    setup = pathlib.Path(__file__).resolve().parent.parent.joinpath("setup.sh").read_text(
        encoding="utf-8")
    assert [ln for ln in setup.splitlines()
            if ln.startswith("export BLUETEAM_LANGGRAPH_DB")] == []
    assert "BLUETEAM_LANGGRAPH_DB" in setup


def test_no_db_keeps_random_threads(monkeypatch):
    monkeypatch.setattr(ig, "_DB_PATH", "")
    first = asyncio.run(ig.run_investigation(srcip="203.0.113.10"))
    second = asyncio.run(ig.run_investigation(srcip="203.0.113.10"))
    assert first["prior_runs"] == 0
    assert second["prior_runs"] == 0
    assert ig._RUN_MARKER not in first["steps"] + second["steps"]


@durable
def test_repeat_run_sees_the_previous_one(tmp_path, monkeypatch):
    monkeypatch.setattr(ig, "_DB_PATH", str(tmp_path / "lg.db"))
    first = asyncio.run(ig.run_investigation(srcip="203.0.113.11"))
    second = asyncio.run(ig.run_investigation(srcip="203.0.113.11"))
    assert first["prior_runs"] == 0
    assert second["prior_runs"] == 1


@durable
def test_subjects_do_not_share_a_thread(tmp_path, monkeypatch):
    monkeypatch.setattr(ig, "_DB_PATH", str(tmp_path / "lg.db"))
    asyncio.run(ig.run_investigation(srcip="203.0.113.12"))
    other = asyncio.run(ig.run_investigation(srcip="203.0.113.99"))
    again = asyncio.run(ig.run_investigation(srcip="203.0.113.12"))
    # Subject B starts at zero; subject A's second run sees exactly one prior run,
    # not the two it would see if B had landed on A's thread.
    assert other["prior_runs"] == 0
    assert again["prior_runs"] == 1


@durable
def test_checkpoint_is_addressable_by_subject(tmp_path, monkeypatch):
    db = str(tmp_path / "lg.db")
    monkeypatch.setattr(ig, "_DB_PATH", db)
    ip = "203.0.113.13"
    first = asyncio.run(ig.run_investigation(srcip=ip))
    asyncio.run(ig.run_investigation(srcip=ip))
    stored = asyncio.run(_stored_steps(db, ig.subject_key("srcip", ip)))
    assert stored.count(ig._RUN_MARKER) == 2
    assert set(first["steps"]) <= set(stored)


@durable
def test_repeat_run_does_not_reuse_the_previous_fp_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(ig, "_DB_PATH", str(tmp_path / "lg.db"))
    ip = "203.0.113.14"
    false_positive_kb.register_false_positive(ip, source="verdict", reason="test noise")
    first = asyncio.run(ig.run_investigation(srcip=ip, check_false_positive=True))
    second = asyncio.run(ig.run_investigation(srcip=ip))
    assert first["fp_validation"]["verdict"] == "suppressed_exact"
    assert second["fp_validation"] is None


@durable
def test_checkpointed_log_is_capped(tmp_path, monkeypatch):
    db = str(tmp_path / "lg.db")
    monkeypatch.setattr(ig, "_DB_PATH", db)
    monkeypatch.setattr(ig, "_STEP_LOG_CAP", 5)
    ip = "203.0.113.15"
    asyncio.run(ig.run_investigation(srcip=ip))
    second = asyncio.run(ig.run_investigation(srcip=ip))
    assert 0 < len(second["steps"]) <= 5
    assert len(asyncio.run(_stored_steps(db, ig.subject_key("srcip", ip)))) <= 5


@durable
def test_checkpoint_written_with_the_old_reducer_still_opens(tmp_path, monkeypatch):
    db = str(tmp_path / "old.db")
    ip = "203.0.113.16"
    thread = ig.thread_id_for(db, ig.subject_key("srcip", ip))
    asyncio.run(_write_legacy_checkpoint(db, thread))
    monkeypatch.setattr(ig, "_DB_PATH", db)
    result = asyncio.run(ig.run_investigation(srcip=ip))
    assert result["status"] in {"complete", "degraded"}
    assert result["steps"]
    assert "legacy step" not in result["steps"]


@durable
def test_fp_validator_does_not_reuse_a_degraded_route(tmp_path, monkeypatch):
    monkeypatch.setattr(fpv, "_DB_PATH", str(tmp_path / "fp.db"))
    ip = "203.0.113.17"
    first = asyncio.run(fpv.run_fp_validation(ip, "ssh auth failure"))
    assert first["verdict"] == "validation_incomplete"
    false_positive_kb.register_false_positive(ip, source="verdict", reason="test noise")
    second = asyncio.run(fpv.run_fp_validation(ip, "ssh auth failure"))
    assert second["verdict"] == "suppressed_exact"
    assert ig._RUN_MARKER not in second["steps"] + second["errors"]
