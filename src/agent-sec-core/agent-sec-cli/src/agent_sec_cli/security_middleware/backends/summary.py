"""Summary backend — future stub for security event aggregation."""


from typing import Any

from agent_sec_cli.security_middleware.backends.base import BaseBackend
from agent_sec_cli.security_middleware.context import RequestContext
from agent_sec_cli.security_middleware.result import ActionResult


class SummaryBackend(BaseBackend):
    """Placeholder for security event summary and reporting.

    This backend will eventually aggregate events from the JSONL log
    and produce time-windowed, categorised reports.
    """

    def execute(self, ctx: RequestContext, **kwargs: Any) -> ActionResult:
        """Not yet implemented — always returns failure."""
        return ActionResult(
            success=False,
            error="Security event summary not yet implemented",
        )
