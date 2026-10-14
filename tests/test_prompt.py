"""The ENTER prompts: ENTER, EOF, and Ctrl-C on a real terminal."""

import os
import select
import signal
import subprocess
import sys
import time

import pytest

PROMPT = (
    "import asyncio; from crimson_headless_passkey.flows import prompt; "
    "print(repr(asyncio.run(prompt('> '))))"
)


def run_prompt(stdin):
    return subprocess.run(
        [sys.executable, "-c", PROMPT], stdin=stdin, capture_output=True, text=True, timeout=30
    )


def test_returns_the_line_without_newline():
    result = subprocess.run(
        [sys.executable, "-c", PROMPT], input="hello\n", capture_output=True, text=True, timeout=30
    )
    assert result.stdout.endswith("'hello'\n")


def test_eof_counts_as_enter():
    result = run_prompt(subprocess.DEVNULL)
    assert result.stdout.endswith("''\n")


@pytest.mark.skipif(os.name != "posix", reason="needs a pseudo-terminal")
def test_ctrl_c_at_a_terminal_prompt_exits_promptly():
    """A worker thread blocked in input() made Ctrl-C hang until ENTER was pressed."""
    import pty

    pid, fd = pty.fork()
    if pid == 0:  # child: wait at the prompt on a real terminal
        os.execv(sys.executable, [sys.executable, "-c", PROMPT])

    def drain(seconds):
        # Keep reading, or the child blocks writing its traceback to a full terminal.
        output, end = b"", time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    output += os.read(fd, 65536)
                except OSError:
                    break
        return output

    try:
        deadline = time.monotonic() + 20
        seen = b""
        while b"> " not in seen and time.monotonic() < deadline:
            seen += drain(0.1)
        assert b"> " in seen, "prompt never appeared"

        os.kill(pid, signal.SIGINT)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            drain(0.05)
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                return
        pytest.fail("still running 5s after Ctrl-C")
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass
        os.close(fd)
