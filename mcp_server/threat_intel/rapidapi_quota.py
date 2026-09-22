#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Account-wide RapidAPI budget guard.
The RapidAPI account carries one hard limit shared by every subscribed product, so a
scheduled report and a live incident draw from the same pool. Nothing in the cache or
the rate limiter protects that pool: the rate limiter bounds requests per second and
the account limit is a count per month, two constraints that never bind together.

Policy enforced here:
- Default 0. A budget that was never armed cannot be spent, so a daily report run
  cannot eat the month by accident.
- Every product draws from one counter, because the account is metered as one.
- The arm window expires on its own, so an incident window does not stay open.
- Spend and window survive a restart. A restarted process must not hand back a
  budget the account has already been billed for.
"""
from __future__ import annotations
import logging, time
from datetime import datetime, timezone
from typing import Any
from mcp_server.core.exceptions import ThreatIntelError

logger = logging.getLogger("blue_team_mcp.threat_intel.rapidapi_quota")

# RapidAPI free tier on this account: a hard 100 requests per month across all
# subscribed products, with a 1000/hour burst limit that a 100/month budget can
# never reach. Overridable so the guard follows the plan, not this comment.
DEFAULT_MONTHLY_CAP = 100


def _reset_date() -> str:
    """First day of next month, UTC. The message must say when the pool refills."""
    now = datetime.now(timezone.utc)
    year, month = (now.year + 1, 1) if now.month == 12 else (now.year, now.month + 1)
    return f"{year:04d}-{month:02d}-01"


class RapidApiBudget:
    """Time-boxed, fail closed request budget for every RapidAPI call.
    ``budget`` is what the operator armed for this window; ``monthly_cap`` is the
    account ceiling. The effective allowance is the smaller of the two, so a typo in
    the arm amount cannot exceed what the account will actually serve.
    """
    def __init__(self, budget: int = 0, hours: float = 8.0,
                 monthly_cap: int = DEFAULT_MONTHLY_CAP, store: Any = None):
        self._budget = max(0, int(budget))
        self._hours = max(0.0, float(hours))
        self._cap = max(0, int(monthly_cap))
        self._store = store
        self._month = self._current_month()
        self._spent = 0
        self._armed_at = 0.0
        if store is not None:
            self._resume(store.get_quota())

    @staticmethod
    def _current_month() -> str:
        return time.strftime("%Y-%m", time.gmtime())

    def _resume(self, state: dict[str, Any]) -> None:
        if state.get("m") != self._month:
            return
        try:
            self._spent = max(0, int(state.get("s", 0)))
        except (TypeError, ValueError):
            self._spent = 0
        try:
            self._armed_at = max(0.0, float(state.get("a", 0.0)))
        except (TypeError, ValueError):
            self._armed_at = 0.0

    def _persist(self) -> None:
        if self._store is not None:
            self._store.set_quota({"m": self._month, "s": self._spent, "a": self._armed_at})

    def _roll(self) -> None:
        month = self._current_month()
        if month != self._month:
            self._month, self._spent, self._armed_at = month, 0, 0.0
        # The window starts on first spend, not at import: a server that idles until
        # 03:00 should still get its full window when the incident actually starts.
        if self._budget > 0 and not self._armed_at:
            self._armed_at = time.time()
            self._persist()

    @property
    def allowance(self) -> int:
        return min(self._budget, self._cap)

    @property
    def remaining(self) -> int:
        return max(0, self.allowance - self._spent)

    def state(self) -> dict[str, Any]:
        """Operational view for error text and the metrics resource."""
        return {
            "armed": self._budget,
            "allowance": self.allowance,
            "spent": self._spent,
            "remaining": self.remaining,
            "month": self._month,
            "window_hours": self._hours,
            "window_open": bool(self._armed_at) and not self._expired(),
            "resets": _reset_date(),
        }

    def _expired(self) -> bool:
        if self._hours <= 0 or not self._armed_at:
            return not self._armed_at
        return (time.time() - self._armed_at) > self._hours * 3600

    def check(self) -> None:
        """Refuse before the request leaves the process.
        Discovering an exhausted pool from a 429 costs a round trip, a slot in the
        report the LLM is writing, and a confusing error. The local counter knows.
        """
        self._roll()
        if self.allowance <= 0:
            raise ThreatIntelError(
                "[rapidapi] Budget closed: 0 requests armed. The account-wide RapidAPI "
                "pool is reserved for live incident triage, and scheduled reports use "
                "the quota-free providers (blueteam_threat_intel_aggregate, "
                "crowdsec_ip_reputation). Set BLUETEAM_RAPIDAPI_BUDGET and restart to arm."
            )
        if self.remaining <= 0:
            raise ThreatIntelError(
                f"[rapidapi] Budget exhausted: {self._spent}/{self.allowance} requests "
                f"used this month across every RapidAPI product. The pool resets "
                f"{_reset_date()}."
            )
        if self._expired():
            raise ThreatIntelError(
                f"[rapidapi] Arm window closed after {self._hours:g}h with "
                f"{self.remaining} request(s) unspent. Restart the server to arm a new "
                f"window; the monthly counter is preserved."
            )

    def charge(self) -> None:
        """Count one request. TTL-cache hits are free and must not reach here."""
        self._spent += 1
        self._persist()
        logger.info("RapidAPI budget %d/%d used this month.", self._spent, self.allowance)
