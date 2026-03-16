from __future__ import annotations

import asyncio
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from utils.logger import get_logger

logger = get_logger("securefix.shell")

# Characters that must not appear in shell tokens passed to subprocess
_INJECTION_PATTERN = re.compile(r"[;&|`$><\\\n]")

# Absolute allow-list of executables SecureFix may invoke
_ALLOWED_EXECUTABLES = frozenset(
    {
        "npm",
        "npx",
        "node",
        "pip",
        "pip3",
        "pip-audit",
        "safety",
        "pytest",
        "python",
        "python3",
        "git",
        "poetry",
        "pipenv",
    }
)


@dataclass
class CommandResult:
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cwd: Optional[str] = None
    env_used: Dict[str, str] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return self.stdout

    def __repr__(self) -> str:
        return (
            f"CommandResult(cmd={self.command!r}, exit={self.exit_code}, "
            f"ok={self.success})"
        )


def _validate_command(args: List[str]) -> None:
    """
    Perform security checks before executing any shell command.

    Raises ValueError if:
    - The executable is not in the allow-list
    - Any argument contains shell metacharacters
    - Any path argument escapes expected boundaries
    """
    if not args:
        raise ValueError("Empty command list")

    executable = Path(args[0]).name
    if executable not in _ALLOWED_EXECUTABLES:
        raise ValueError(
            f"Executable '{executable}' is not in the SecureFix allow-list. "
            f"Allowed: {sorted(_ALLOWED_EXECUTABLES)}"
        )

    for token in args[1:]:
        if _INJECTION_PATTERN.search(token):
            raise ValueError(
                f"Potentially unsafe shell metacharacter detected in argument: {token!r}"
            )


def run_command(
    args: List[str],
    cwd: Optional[str] = None,
    timeout: int = 120,
    env: Optional[Dict[str, str]] = None,
    check: bool = False,
) -> CommandResult:
    """
    Synchronously run a subprocess with security validation.

    Args:
        args:    Tokenised command (no shell interpolation).
        cwd:     Working directory for the process.
        timeout: Hard wall-clock timeout in seconds.
        env:     Optional environment dict (merged with os.environ).
        check:   If True, raises subprocess.CalledProcessError on non-zero exit.
    """
    _validate_command(args)

    import os

    merged_env = {**os.environ, **(env or {})}

    logger.debug("running_command", command=args, cwd=cwd)

    timed_out = False
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged_env,
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -1
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        logger.warning("command_timed_out", command=args, timeout=timeout)

    cmd_result = CommandResult(
        command=args,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        cwd=cwd,
    )

    if check and not cmd_result.success:
        raise subprocess.CalledProcessError(
            exit_code,
            args,
            output=stdout,
            stderr=stderr,
        )

    logger.debug(
        "command_completed",
        command=args,
        exit_code=exit_code,
        success=cmd_result.success,
    )
    return cmd_result


async def run_command_async(
    args: List[str],
    cwd: Optional[str] = None,
    timeout: int = 120,
    env: Optional[Dict[str, str]] = None,
) -> CommandResult:
    """
    Asynchronously run a subprocess with security validation.
    Non-blocking: uses asyncio.create_subprocess_exec.
    """
    _validate_command(args)

    import os

    merged_env = {**os.environ, **(env or {})}

    logger.debug("running_command_async", command=args, cwd=cwd)

    timed_out = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=merged_env,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            timed_out = True
            stdout_bytes, stderr_bytes = b"", b""

        exit_code = proc.returncode if proc.returncode is not None else -1
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
    except Exception as exc:
        logger.error("command_exec_error", command=args, error=str(exc))
        raise

    return CommandResult(
        command=args,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        cwd=cwd,
    )
