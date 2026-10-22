"""Process status codes and the exception hierarchy the CLI maps to them.

Exit code 1 used to mean "login did not finish" for every reason. 0.3.0 splits
it so a bot can tell an auth failure apart from a human-required step, a network
error or a missing resource (BREAKING; see README and CHANGELOG). The numbers
are a public contract: keep them stable.
"""

from __future__ import annotations

# Status strings flow from the browser flow and the fetcher; EXIT_CODES maps
# each to a process exit code. Keeping the two separate lets the library report
# a status without caring about process codes.
STATUS_OK = "ok"
STATUS_AUTH_FAILED = "auth_failed"
STATUS_CONFIG = "config"
STATUS_NEEDS_HUMAN = "needs_human"
STATUS_NETWORK = "network"
STATUS_NOT_FOUND = "not_found"
STATUS_PARTIAL = "partial"
STATUS_INTERRUPTED = "interrupted"

EXIT_OK = 0
EXIT_AUTH_FAILED = 1
EXIT_CONFIG = 2
EXIT_NEEDS_HUMAN = 3
EXIT_NETWORK = 4
EXIT_NOT_FOUND = 5
EXIT_PARTIAL = 6
EXIT_INTERRUPTED = 130

EXIT_CODES = {
    STATUS_OK: EXIT_OK,
    STATUS_AUTH_FAILED: EXIT_AUTH_FAILED,
    STATUS_CONFIG: EXIT_CONFIG,
    STATUS_NEEDS_HUMAN: EXIT_NEEDS_HUMAN,
    STATUS_NETWORK: EXIT_NETWORK,
    STATUS_NOT_FOUND: EXIT_NOT_FOUND,
    STATUS_PARTIAL: EXIT_PARTIAL,
    STATUS_INTERRUPTED: EXIT_INTERRUPTED,
}


def exit_code_for(status: str) -> int:
    """The process exit code for a status string (unknown statuses are a config error)."""
    return EXIT_CODES.get(status, EXIT_CONFIG)
