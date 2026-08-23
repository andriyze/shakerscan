import asyncio
import hashlib
import os
import re
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from dataclasses import dataclass
from typing import Any

try:
    from .request_meter import RequestBudgetExceeded, get_request_meter
except ImportError:  # pragma: no cover - flat-module fallback
    from request_meter import RequestBudgetExceeded, get_request_meter

try:
    from ..redaction import redact_text as _shared_redact_text
except ImportError:  # pragma: no cover - flat-module fallback
    from redaction import redact_text as _shared_redact_text

try:  # sibling module; tolerate flat (/app) execution
    from .adaptive_throttle import get_throttle as _get_active_throttle
except ImportError:  # pragma: no cover - flat-module fallback
    try:
        from adaptive_throttle import get_throttle as _get_active_throttle
    except ImportError:
        _get_active_throttle = None

# Disable SSL verification for testing
_ssl_context = ssl.create_default_context()
_ssl_context.check_hostname = False
_ssl_context.verify_mode = ssl.CERT_NONE

# File extensions that indicate a file path (not a directory) for hash route normalization.
# Used to normalize URLs like /app/index.html#/route -> /app/#/route
HASH_ROUTE_FILE_EXTENSIONS = frozenset({
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".shtml"
})


def normalize_hash_route_url(hash_route: str, current_url: str) -> str | None:
    """
    Normalize a hash route fragment into a full URL.

    Handles SPA-style hash routes (#/ or #!/) by:
    1. Preserving the base path from current_url
    2. Normalizing file paths (e.g., index.html) to their parent directory
    3. Building a complete URL with the hash route appended

    Args:
        hash_route: The hash route fragment (e.g., "#/search" or "#!/page")
        current_url: The current page URL to use as base

    Returns:
        Full URL with hash route, or None if not a valid hash route

    Examples:
        >>> normalize_hash_route_url("#/search", "https://host/app/")
        "https://host/app/#/search"
        >>> normalize_hash_route_url("#/page", "https://host/app/index.html")
        "https://host/app/#/page"
        >>> normalize_hash_route_url("#top", "https://host/")  # anchor-only
        None
    """
    import os

    if not hash_route.startswith("#"):
        return None
    if not (hash_route.startswith("#/") or hash_route.startswith("#!/")):
        return None  # Skip anchor-only fragments like #top

    parsed = urllib.parse.urlparse(current_url)
    base_path = parsed.path or ""

    # If path looks like a file (not ending in / and has common file extension),
    # use parent directory. Be conservative to avoid stripping version paths like /v1.2/
    if not base_path.endswith("/"):
        basename = os.path.basename(base_path)
        ext = os.path.splitext(basename)[1].lower()
        if ext in HASH_ROUTE_FILE_EXTENSIONS:
            base_path = os.path.dirname(base_path)

    base_path = base_path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{base_path}/{hash_route}"

# Limit concurrent subprocess executions to prevent resource exhaustion
# Default: 15 concurrent subprocesses (tunable via SCANNER_MAX_CONCURRENT env var)
_MAX_CONCURRENT_SUBPROCESSES = int(os.environ.get("SCANNER_MAX_CONCURRENT", "15"))
_subprocess_semaphore: asyncio.Semaphore | None = None
_semaphore_loop: asyncio.AbstractEventLoop | None = None
_SUBPROCESS_RECEIPT_LIMIT = int(os.environ.get("SCANNER_SUBPROCESS_RECEIPT_LIMIT", "200"))
_SUBPROCESS_PREVIEW_BYTES = 500
_SUBPROCESS_ARTIFACT_MAX_BYTES = int(os.environ.get("SCANNER_SUBPROCESS_ARTIFACT_MAX_BYTES", "8192"))
_subprocess_receipts: list[dict[str, Any]] = []


_SENSITIVE_ARG_MARKERS = (
    "token", "secret", "password", "passwd", "authorization", "cookie",
    "apikey", "api_key", "key=", "jwt", "csrf", "xsrf", "signature",
)


def _redact_arg(value: Any) -> str:
    text = str(value if value is not None else "")
    lowered = text.lower()
    if any(marker in lowered for marker in _SENSITIVE_ARG_MARKERS):
        return "[REDACTED]"
    if len(text) > 240:
        return text[:120] + "...[truncated]..." + text[-40:]
    return text


def _redacted_argv(cmd: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for arg in cmd or []:
        text = str(arg)
        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
            continue
        if text in {"-H", "--header", "-b", "--cookie", "--cookie-jar", "-d", "--data", "--data-raw", "--data-binary"}:
            redacted.append(text)
            redact_next = True
            continue
        redacted.append(_redact_arg(text))
    return redacted


def _curl_http_method(cmd: list[str]) -> str:
    """Resolve curl's effective method without inspecting request content."""
    explicit: str | None = None
    inferred = "GET"
    index = 1
    while index < len(cmd):
        value = str(cmd[index])
        if value in {"-X", "--request"} and index + 1 < len(cmd):
            explicit = str(cmd[index + 1]).strip().upper()
            index += 2
            continue
        if value.startswith("--request="):
            explicit = value.split("=", 1)[1].strip().upper()
        elif value in {"-I", "--head"}:
            inferred = "HEAD"
        elif value in {"-T", "--upload-file"} or value.startswith("--upload-file="):
            inferred = "PUT"
        elif value in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "--json"}:
            inferred = "POST"
        elif value.startswith(("--data=", "--data-raw=", "--data-binary=", "--data-urlencode=", "--form=", "--json=")):
            inferred = "POST"
        index += 1
    return explicit or inferred


def _redact_output_text(value: Any) -> str:
    text = str(_shared_redact_text(str(value if value is not None else "")))
    text = re.sub(r"(?i)\b(?:sk|pk)_[a-z0-9_=-]{12,}\b", "[REDACTED]", text)
    # Strip NUL bytes: they are valid UTF-8 and survive decoding, but Postgres rejects
    #  in jsonb, so an unstripped NUL makes the receipt/artifact INSERT raise and the
    # record is silently dropped (binary tool output would leave no receipt at all).
    text = text.replace("\x00", "")
    return text


def _output_artifact(stream_name: str, value: str) -> dict[str, Any] | None:
    redacted = _redact_output_text(value)
    if len(redacted) <= _SUBPROCESS_PREVIEW_BYTES:
        return None
    max_bytes = max(0, _SUBPROCESS_ARTIFACT_MAX_BYTES)
    if max_bytes <= 0:
        return None
    encoded = redacted.encode("utf-8", "ignore")
    captured = encoded[:max_bytes].decode("utf-8", "ignore")
    return {
        "stream": stream_name,
        "content": captured,
        "content_sha256": hashlib.sha256(captured.encode("utf-8", "ignore")).hexdigest(),
        "original_length": len(value or ""),
        "redacted_length": len(redacted),
        "captured_length": len(captured),
        "truncated": len(encoded) > max_bytes,
        "redaction_profile": "subprocess_output_redact_v1",
    }


def reset_subprocess_receipts() -> None:
    _subprocess_receipts.clear()


def snapshot_subprocess_receipts() -> list[dict[str, Any]]:
    return [dict(item) for item in _subprocess_receipts]


def _record_subprocess_receipt(
    cmd: list[str],
    *,
    timeout_seconds: int,
    exit_code: int,
    timed_out: bool,
    started_at: float,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
) -> None:
    if len(_subprocess_receipts) >= max(0, _SUBPROCESS_RECEIPT_LIMIT):
        return
    redacted = _redacted_argv(cmd or [])
    tool_name = redacted[0] if redacted else "subprocess"
    status = "timeout" if timed_out else "success" if exit_code == 0 else "failed"
    parser_status = "partial_available" if timed_out and stdout else "not_applicable" if timed_out else "not_run"
    now = time.monotonic()
    stdout_text = str(stdout or "")
    stderr_text = str(stderr or error or "")
    stdout_preview = _redact_output_text(stdout_text)[:_SUBPROCESS_PREVIEW_BYTES]
    stderr_preview = _redact_output_text(stderr_text)[:_SUBPROCESS_PREVIEW_BYTES]
    stdout_artifact = _output_artifact("stdout", stdout_text)
    stderr_artifact = _output_artifact("stderr", stderr_text)
    receipt = {
        "tool_name": tool_name,
        "status": status,
        "parser_status": parser_status,
        "exit_code": int(exit_code),
        "timed_out": bool(timed_out),
        "timeout_seconds": int(timeout_seconds),
        "duration_ms": int(max(0, now - started_at) * 1000),
        "redacted_argv": redacted,
        "command_hash": hashlib.sha256("\x00".join(redacted).encode("utf-8", "ignore")).hexdigest(),
        "stdout_length": len(stdout_text),
        "stderr_length": len(stderr_text),
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
    }
    if stdout_artifact:
        receipt["stdout_artifact"] = stdout_artifact
    if stderr_artifact:
        receipt["stderr_artifact"] = stderr_artifact
    _subprocess_receipts.append(receipt)


def _get_semaphore() -> asyncio.Semaphore:
    """Get or create the subprocess semaphore (lazy initialization for event loop compatibility).

    Recreates the semaphore if the event loop has changed to avoid
    'attached to a different loop' errors.
    """
    global _subprocess_semaphore, _semaphore_loop
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if _subprocess_semaphore is None or _semaphore_loop is not current_loop:
        _subprocess_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_SUBPROCESSES)
        _semaphore_loop = current_loop
    return _subprocess_semaphore


async def run(
    cmd: list[str],
    timeout: int = 60,
    input_text: str | None = None,
    retry: int = 0,
    cancel_check: Any = None,
) -> tuple[str, str, int]:
    """Execute command with optional retry logic (shared across modules).

    Uses a semaphore to limit concurrent subprocess executions and prevent resource exhaustion.
    """
    if os.environ.get("SHAKERSCAN_CANONICAL_REPORT_ONLY", "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        error = "canonical report assembly cannot execute subprocesses"
        _record_subprocess_receipt(
            cmd,
            timeout_seconds=timeout,
            exit_code=75,
            timed_out=False,
            started_at=time.monotonic(),
            error=error,
        )
        return "", error, 75
    # The adaptive throttle only engages for HTTP (curl) requests during an active
    # scan; it paces the shared request stream so a single-process target under
    # load stops returning degraded responses that make detectors flake. No-op
    # unless explicitly enabled (non-active scans are unaffected).
    tool_basename = os.path.basename(cmd[0]) if cmd else "subprocess"
    is_http_request = tool_basename == "curl"
    request_urls = [
        value for value in cmd
        if isinstance(value, str) and value.startswith(("http://", "https://"))
    ]
    request_url = request_urls[-1] if request_urls else None
    unmetered_network_tools = {
        "dalfox", "ffuf", "httpx", "katana", "meg", "nikto", "nuclei",
        "nmap", "naabu", "openssl", "sqlmap", "sslyze", "subfinder",
        "testssl", "testssl.sh", "tlsx", "xsstrike.py",
    }
    meter = get_request_meter()
    if is_http_request and meter.enforcing and request_url and "-L" in cmd:
        bounded_cmd: list[str] = []
        skip_next = False
        for value in cmd:
            if skip_next:
                skip_next = False
                continue
            if value in {"-L", "--location"}:
                continue
            if value == "--max-redirs":
                skip_next = True
                continue
            bounded_cmd.append(value)
        cmd = bounded_cmd
    # Version/help probes are local process checks, not target traffic. Treating
    # ``nuclei -version`` as an unmetered network invocation made every
    # enforced Fleet scan claim that Nuclei was not installed before the real
    # scan command was even considered. Keep the exception deliberately
    # narrow: only a two-argument, known local probe bypasses the network-tool
    # guard; the actual scanner invocation still fails closed in enforce mode.
    local_tool_probe = (
        len(cmd) == 2
        and cmd[1] in {"-version", "--version", "version", "-h", "--help"}
    )
    if tool_basename in unmetered_network_tools and not local_tool_probe:
        try:
            meter.record_unmetered_tool(tool=tool_basename, target_url=request_url)
        except RequestBudgetExceeded:
            return "", "unmetered network tool is disabled by the request budget", 75
    _throttle = _get_active_throttle() if (is_http_request and _get_active_throttle) else None

    async with _get_semaphore():
        for attempt in range(retry + 1):
            proc = None
            metered_request = False
            # Every external tool gets its own process group.  This lets the
            # shared timeout/cancellation path reap grandchildren as well as the
            # immediate process (nuclei/sqlmap regularly spawn helpers).  The
            # worker first signals SHAKERSCAN_CANCEL_FILE, giving this runner a
            # chance to kill that group before it terminates scanner.py.
            use_process_group = os.name == "posix"
            tool_name = cmd[0] if cmd else "subprocess"
            if is_http_request and request_url:
                try:
                    metered_request = meter.before_request(
                        phase="curl",
                        url=request_url,
                        method=_curl_http_method(cmd),
                        retry=attempt > 0,
                    )
                except RequestBudgetExceeded:
                    return "", "request budget exhausted before HTTP request", 75
            if _throttle is not None:
                await _throttle.before()
            _req_started = time.monotonic()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE if input_text is not None else None,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=use_process_group,
                )
                cancel_watchers: list[asyncio.Task] = []
                cancelled_by_callback = False

                async def _kill_child_group() -> None:
                    if proc is None or proc.returncode is not None:
                        return
                    try:
                        if use_process_group:
                            os.killpg(proc.pid, signal.SIGKILL)
                        else:
                            proc.kill()
                    except ProcessLookupError:
                        pass

                if os.environ.get("SHAKERSCAN_CANCEL_FILE"):
                    async def _cancel_child_group() -> None:
                        from .cancellation import wait_for_scanner_cancel

                        await wait_for_scanner_cancel()
                        await _kill_child_group()

                    cancel_watchers.append(asyncio.create_task(_cancel_child_group()))

                if callable(cancel_check):
                    async def _cancel_from_callback() -> None:
                        nonlocal cancelled_by_callback
                        while proc is not None and proc.returncode is None:
                            requested = cancel_check()
                            if hasattr(requested, "__await__"):
                                requested = await requested
                            if bool(requested):
                                cancelled_by_callback = True
                                await _kill_child_group()
                                return
                            await asyncio.sleep(0.25)

                    cancel_watchers.append(asyncio.create_task(_cancel_from_callback()))
                try:
                    out_b, err_b = await asyncio.wait_for(
                        proc.communicate(input=input_text.encode() if input_text is not None else None),
                        timeout=timeout,
                    )
                    from .cancellation import scanner_cancel_requested
                    if cancelled_by_callback or scanner_cancel_requested():
                        _record_subprocess_receipt(
                            cmd,
                            timeout_seconds=timeout,
                            exit_code=130,
                            timed_out=False,
                            started_at=_req_started,
                            stderr="scanner cancellation requested",
                        )
                        return "", "scanner cancellation requested", 130
                except asyncio.CancelledError:
                    if proc is not None:
                        try:
                            if use_process_group:
                                os.killpg(proc.pid, signal.SIGKILL)
                                print("[run] Killed subprocess group after cancellation", file=sys.stderr)
                            else:
                                proc.kill()
                            await proc.wait()
                        except Exception:
                            pass
                    raise
                except TimeoutError:
                    if use_process_group:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                            print("[run] Killed subprocess group after timeout", file=sys.stderr)
                        except ProcessLookupError:
                            pass
                    else:
                        proc.kill()
                    await proc.wait()  # Reap zombie process
                    if _throttle is not None:
                        # A timeout is the strongest degradation signal.
                        _throttle.record(rc=124, elapsed=timeout)
                    if attempt < retry:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    _record_subprocess_receipt(
                        cmd,
                        timeout_seconds=timeout,
                        exit_code=124,
                        timed_out=True,
                        started_at=_req_started,
                        stderr=f"timeout after {timeout}s",
                    )
                    return "", f"timeout after {timeout}s", 124
                finally:
                    for cancel_watch in cancel_watchers:
                        cancel_watch.cancel()
                    for cancel_watch in cancel_watchers:
                        try:
                            await cancel_watch
                        except BaseException:
                            pass
                out = out_b.decode(errors="ignore")
                err = err_b.decode(errors="ignore")
                if _throttle is not None:
                    _throttle.record(rc=proc.returncode, elapsed=time.monotonic() - _req_started)
                _record_subprocess_receipt(
                    cmd,
                    timeout_seconds=timeout,
                    exit_code=int(proc.returncode or 0),
                    timed_out=False,
                    started_at=_req_started,
                    stdout=out,
                    stderr=err,
                )
                return out.strip(), err.strip(), proc.returncode
            except asyncio.CancelledError:
                if proc is not None:
                    try:
                        if use_process_group:
                            os.killpg(proc.pid, signal.SIGKILL)
                            print("[run] Killed subprocess group after cancellation", file=sys.stderr)
                        else:
                            proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
                raise
            except Exception as exc:
                if proc is not None:
                    try:
                        if use_process_group:
                            os.killpg(proc.pid, signal.SIGKILL)
                            print("[run] Killed subprocess group after execution failure", file=sys.stderr)
                        else:
                            proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
                if attempt < retry:
                    await asyncio.sleep(2 ** attempt)
                    continue
                _record_subprocess_receipt(
                    cmd,
                    timeout_seconds=timeout,
                    exit_code=1,
                    timed_out=False,
                    started_at=_req_started,
                    error=f"subprocess execution failed ({type(exc).__name__})",
                )
                return "", f"subprocess execution failed ({type(exc).__name__})", 1
            finally:
                if metered_request:
                    meter.record_completion(phase="curl", url=request_url)
        return "", "Max retries exceeded", 1


@dataclass(frozen=True)
class StreamingRunResult:
    stdout: str
    stderr: str
    returncode: int
    status: str
    partial: bool = False
    timed_out: bool = False
    soft_deadline_reached: bool = False
    cancelled: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


async def run_streaming(
    cmd: list[str],
    *,
    soft_timeout: float,
    flush_grace: float = 30.0,
    hard_timeout: float | None = None,
    input_text: str | None = None,
    cancel_check: Any = None,
    on_stdout_line: Any = None,
    max_stdout_bytes: int = 8 * 1024 * 1024,
    max_stderr_bytes: int = 2 * 1024 * 1024,
) -> StreamingRunResult:
    """Run a process without discarding valid output when a deadline is reached.

    At the soft deadline the process group receives SIGINT and may flush for ``flush_grace``.
    A still-running group then receives SIGTERM and may run until ``hard_timeout`` before SIGKILL.
    User cancellation always kills immediately and is returned distinctly from timeout.
    """
    if not cmd:
        raise ValueError("cmd must not be empty")
    soft_timeout = float(soft_timeout)
    flush_grace = float(flush_grace)
    hard_timeout = float(hard_timeout if hard_timeout is not None else soft_timeout + flush_grace)
    if soft_timeout <= 0 or flush_grace < 0 or hard_timeout < soft_timeout + flush_grace:
        raise ValueError("deadlines must satisfy 0 < soft <= soft+flush <= hard")
    if max_stdout_bytes < 0 or max_stderr_bytes < 0:
        raise ValueError("output limits must be non-negative")
    if os.environ.get("SHAKERSCAN_CANONICAL_REPORT_ONLY", "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        return StreamingRunResult(
            stdout="",
            stderr="canonical report assembly cannot execute subprocesses",
            returncode=75,
            status="blocked",
            partial=False,
            timed_out=False,
            soft_deadline_reached=False,
            cancelled=False,
        )

    async with _get_semaphore():
        started = time.monotonic()
        use_process_group = os.name == "posix"
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=use_process_group,
        )
        if input_text is not None and proc.stdin is not None:
            proc.stdin.write(input_text.encode())
            await proc.stdin.drain()
            proc.stdin.close()

        stdout = bytearray()
        stderr = bytearray()
        stdout_truncated = False
        stderr_truncated = False

        async def _read(stream: Any, sink: bytearray, limit: int, *, callback: Any = None) -> bool:
            truncated = False
            while True:
                line = await stream.readline()
                if not line:
                    return truncated
                room = max(0, limit - len(sink))
                if room:
                    sink.extend(line[:room])
                if len(line) > room:
                    truncated = True
                if callback is not None:
                    text = line.decode(errors="replace").rstrip("\r\n")
                    result = callback(text)
                    if hasattr(result, "__await__"):
                        await result

        stdout_task = asyncio.create_task(_read(
            proc.stdout, stdout, max_stdout_bytes, callback=on_stdout_line
        ))
        stderr_task = asyncio.create_task(_read(proc.stderr, stderr, max_stderr_bytes))

        async def _signal(sig: int) -> None:
            if proc.returncode is not None:
                return
            try:
                if use_process_group:
                    os.killpg(proc.pid, sig)
                else:
                    proc.send_signal(sig)
            except ProcessLookupError:
                pass

        cancelled = False
        soft_reached = False
        timed_out = False

        async def _cancel_watch() -> None:
            nonlocal cancelled
            if not callable(cancel_check):
                return
            while proc.returncode is None:
                requested = cancel_check()
                if hasattr(requested, "__await__"):
                    requested = await requested
                if requested:
                    cancelled = True
                    await _signal(signal.SIGKILL)
                    return
                await asyncio.sleep(0.1)

        cancel_task = asyncio.create_task(_cancel_watch())
        try:
            try:
                await asyncio.wait_for(proc.wait(), timeout=soft_timeout)
            except TimeoutError:
                soft_reached = True
                await _signal(signal.SIGINT)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=flush_grace)
                except TimeoutError:
                    await _signal(signal.SIGTERM)
                    remaining = max(0.0, hard_timeout - soft_timeout - flush_grace)
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=remaining)
                    except TimeoutError:
                        timed_out = True
                        await _signal(signal.SIGKILL)
                        await proc.wait()
                if not cancelled:
                    timed_out = True
        except asyncio.CancelledError:
            await _signal(signal.SIGKILL)
            await proc.wait()
            raise
        finally:
            cancel_task.cancel()
            try:
                await cancel_task
            except BaseException:
                pass
            stdout_truncated, stderr_truncated = await asyncio.gather(stdout_task, stderr_task)

        stdout_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")
        if cancelled:
            status, returncode = "cancelled", 130
        elif timed_out:
            status, returncode = "partial" if stdout_text else "timed_out", 124
        else:
            returncode = int(proc.returncode or 0)
            status = "succeeded" if returncode == 0 else "failed"
        partial = bool(timed_out and stdout_text)
        _record_subprocess_receipt(
            cmd,
            timeout_seconds=max(1, int(hard_timeout)),
            exit_code=returncode,
            timed_out=timed_out,
            started_at=started,
            stdout=stdout_text,
            stderr=stderr_text,
        )
        return StreamingRunResult(
            stdout_text, stderr_text, returncode, status, partial, timed_out, soft_reached,
            cancelled, stdout_truncated, stderr_truncated,
        )


def now_utc_iso() -> str:
    return datetime.now(UTC).isoformat()


def sanitize_header_value(value: Any) -> str:
    """Strip CR/LF from a header value to defeat outbound header injection.

    User-supplied auth headers, cookies, and custom header maps flow into
    curl `-H name: value` arguments via this module. A `\\r\\n` in the
    value would let an attacker who can submit a scan inject arbitrary
    additional HTTP request headers against the scan target. Modern curl
    rejects this for `-H`, but the broader scanner toolchain doesn't all
    use modern curl; sanitize defensively at the source.
    """
    if value is None:
        return ""
    return str(value).replace("\r", " ").replace("\n", " ")


def sanitize_header_name(name: Any) -> str:
    """Strip CR/LF and `:` from a header name. Empty result means drop the entry."""
    if name is None:
        return ""
    cleaned = str(name).replace("\r", "").replace("\n", "").replace(":", "")
    return cleaned.strip()


def get_auth_curl_args(auth_session: Any | None = None) -> list[str]:
    """Build curl args for authenticated requests.

    Args:
        auth_session: AuthSession object with cookies and headers config

    Returns:
        List of curl arguments like ['-H', 'Cookie: ...', '-H', 'Authorization: ...']
    """
    args = []
    if auth_session is None:
        return args

    # Get cookies from config and received during session
    cookies = {}
    if hasattr(auth_session, 'config') and hasattr(auth_session.config, 'cookies'):
        cookies.update(auth_session.config.cookies or {})
    if hasattr(auth_session, 'state') and hasattr(auth_session.state, 'cookies_received'):
        cookies.update(auth_session.state.cookies_received or {})

    if cookies:
        sanitized_pairs = [
            f"{sanitize_header_value(k)}={sanitize_header_value(v)}"
            for k, v in cookies.items()
            if sanitize_header_value(k)
        ]
        if sanitized_pairs:
            cookie_str = "; ".join(sanitized_pairs)
            args.extend(["-H", f"Cookie: {cookie_str}"])

    # Get auth headers from config
    if hasattr(auth_session, 'config') and hasattr(auth_session.config, 'headers'):
        headers = auth_session.config.headers or {}
        for name, value in headers.items():
            clean_name = sanitize_header_name(name)
            if not clean_name:
                continue
            args.extend(["-H", f"{clean_name}: {sanitize_header_value(value)}"])

    return args


def get_auth_sqlmap_context(auth_session: Any | None = None) -> tuple[str | None, list[str]]:
    """Build sqlmap cookie/header values for authenticated requests."""
    if auth_session is None:
        return None, []

    cookies: dict[str, str] = {}
    if hasattr(auth_session, "config") and hasattr(auth_session.config, "cookies"):
        cookies.update(auth_session.config.cookies or {})
    if hasattr(auth_session, "state") and hasattr(auth_session.state, "cookies_received"):
        cookies.update(auth_session.state.cookies_received or {})

    cookie_str = (
        "; ".join(
            f"{sanitize_header_value(k)}={sanitize_header_value(v)}"
            for k, v in cookies.items()
            if sanitize_header_value(k)
        )
        if cookies
        else None
    )

    header_lines: list[str] = []
    if hasattr(auth_session, "config") and hasattr(auth_session.config, "headers"):
        headers = auth_session.config.headers or {}
        for name, value in headers.items():
            clean_name = sanitize_header_name(name)
            if not clean_name or clean_name.lower() == "cookie":
                continue
            header_lines.append(f"{clean_name}: {sanitize_header_value(value)}")

    return cookie_str, header_lines


def _host_from_value(value: str | None) -> str | None:
    """Extract hostname from a URL or host string."""
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        # urlparse treats bare hosts as paths, so add a scheme-less prefix.
        parsed = urllib.parse.urlparse(raw if "://" in raw else f"//{raw}")
    except Exception:
        return None
    host = parsed.hostname
    return host.lower() if host else None


def is_in_scope_url(url: str, base_url: str | None, allow_subdomains: bool = True) -> bool:
    """Check if url is in scope for the target base_url."""
    if not url:
        return False
    if not base_url:
        return True
    base_host = _host_from_value(base_url)
    target_host = _host_from_value(url)
    if not base_host or not target_host:
        return False
    if target_host == base_host:
        return True
    if allow_subdomains and target_host.endswith(f".{base_host}"):
        return True
    # Common case: base host is www.example.com, allow apex + subdomains.
    if allow_subdomains and base_host.startswith("www."):
        apex = base_host[4:]
        if target_host == apex or target_host.endswith(f".{apex}"):
            return True
    return False


# =============================================================================
# SPA DETECTION - Detect Single Page Applications with catch-all routing
# =============================================================================

# Random paths unlikely to exist on any real server
_SPA_TEST_PATHS = [
    "/___spa_detect_test_abc123xyz___",
    "/nonexistent-page-7f8a9b0c1d2e",
    "/random-test-path-3k5m7n9p1q",
]


MAX_SIMPLE_FETCH_BYTES = 262_144


async def _fetch_url_simple(url: str, timeout: int = 10, max_bytes: int = MAX_SIMPLE_FETCH_BYTES) -> tuple[int, str, str]:
    """
    Simple URL fetch using urllib (for SPA detection).

    Returns:
        (status_code, body, content_type)
    """
    def _sync_fetch():
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            if max_bytes:
                req.add_header("Range", f"bytes=0-{max_bytes - 1}")
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context) as response:
                status_code = response.getcode()
                body = response.read(max_bytes).decode('utf-8', errors='ignore') if max_bytes else response.read().decode('utf-8', errors='ignore')
                content_type = response.headers.get('Content-Type', '')
                return (status_code, body, content_type)
        except urllib.error.HTTPError as e:
            return (e.code, "", "")
        except Exception:
            return (0, "", "")

    return await asyncio.to_thread(_sync_fetch)


def _compute_content_hash(content: str) -> str:
    """Compute hash of normalized content for comparison."""
    # Normalize: strip whitespace, lowercase, remove dynamic elements
    normalized = content.strip().lower()
    # Remove common dynamic elements (nonces, CSP, timestamps)
    import re
    normalized = re.sub(r'nonce="[^"]*"', 'nonce=""', normalized)
    normalized = re.sub(r'\d{10,}', '0', normalized)  # Remove timestamps
    return hashlib.sha256(normalized.encode()).hexdigest()[:32]


async def detect_spa_catch_all(base_url: str, timeout: int = 10) -> dict[str, Any]:
    """
    Detect if a website is a Single Page Application with catch-all routing.

    SPAs often return HTTP 200 and the same HTML for ALL paths, which causes
    massive false positives in file exposure and forced browsing checks.

    Detection Strategy:
    1. Fetch 3 random non-existent paths
    2. Require all 3 responses to be HTTP 200 with identical content
    3. Require HTML shell-like content AND SPA framework indicators
    4. If any requirement fails, do not classify as SPA catch-all

    Args:
        base_url: Base URL to test (e.g., "https://example.com")
        timeout: Request timeout in seconds

    Returns:
        {
            "is_spa_catch_all": bool,
            "confidence": "high" | "medium" | "low",
            "evidence": {
                "all_paths_200": bool,
                "content_identical": bool,
                "content_type": str,
                "sample_title": str,
                "html_shell": bool,
                "has_spa_indicators": bool
            }
        }
    """
    result = {
        "is_spa_catch_all": False,
        "confidence": "low",
        "evidence": {
            "all_paths_200": False,
            "content_identical": False,
            "content_type": "",
            "sample_title": "",
            "html_shell": False,
            "has_spa_indicators": False,
        }
    }

    responses = []

    # Fetch all test paths concurrently
    tasks = []
    for path in _SPA_TEST_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        tasks.append(_fetch_url_simple(url, timeout))

    try:
        fetch_results = await asyncio.gather(*tasks, return_exceptions=True)
    except Exception:
        return result

    for fetch_result in fetch_results:
        if isinstance(fetch_result, Exception):
            return result  # Error means we can't reliably detect
        status, body, content_type = fetch_result
        responses.append({
            "status": status,
            "body": body,
            "content_type": content_type,
            "hash": _compute_content_hash(body) if body else ""
        })

    # Check if all returned 200
    all_200 = all(r["status"] == 200 for r in responses)
    result["evidence"]["all_paths_200"] = all_200

    if not all_200:
        # At least one path returned non-200 -> not a catch-all SPA
        return result

    # Check if content is identical (or nearly identical)
    hashes = [r["hash"] for r in responses if r["hash"]]
    if not hashes:
        return result

    content_identical = len(set(hashes)) == 1
    result["evidence"]["content_identical"] = content_identical

    if not content_identical:
        # Content differs -> not a catch-all SPA
        return result

    # Extract additional evidence
    first_body = responses[0]["body"]
    result["evidence"]["content_type"] = responses[0]["content_type"]

    # Try to extract page title
    import re
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', first_body, re.IGNORECASE)
    if title_match:
        result["evidence"]["sample_title"] = title_match.group(1).strip()[:100]

    # Require HTML shell-like content. Uniform JSON or text responses are ambiguous
    # (e.g., gateway/WAF/login-wall defaults) and should not disable scan phases.
    sample = first_body[:4000].lower()
    content_type = (responses[0]["content_type"] or "").lower()
    html_indicators = ("<!doctype", "<html", "<head", "<body", "<script", "<title")
    html_indicator_count = sum(1 for token in html_indicators if token in sample)
    is_html_shell = ("html" in content_type) or html_indicator_count >= 2
    result["evidence"]["html_shell"] = is_html_shell

    if not is_html_shell:
        return result

    # Detect SPA frameworks in the response
    spa_indicators = [
        'id="root"',  # React
        'id="app"',   # Vue
        'ng-app',     # Angular
        '__NEXT_DATA__',  # Next.js
        '__NUXT__',   # Nuxt.js
        'data-reactroot',
        'window.__INITIAL_STATE__',
    ]

    has_spa_indicators = any(ind.lower() in sample for ind in spa_indicators)
    result["evidence"]["has_spa_indicators"] = has_spa_indicators

    # Only high-confidence detections should suppress discovery/testing phases.
    result["is_spa_catch_all"] = has_spa_indicators
    result["confidence"] = "high" if has_spa_indicators else "medium"

    return result


# =============================================================================
# CONTENT VALIDATION - Validate file content matches expected type
# =============================================================================

# Content signatures for different file types
CONTENT_SIGNATURES = {
    # CI/CD files
    "yaml_cicd": {
        "patterns": ["jobs:", "steps:", "runs-on:", "stage:", "script:", "pipeline:", "stages:"],
        "min_matches": 1,
        "reject_html": True,
    },
    # Package manager files
    "package_json": {
        "patterns": ['"name":', '"version":', '"dependencies":', '"devDependencies":'],
        "min_matches": 1,
        "reject_html": True,
    },
    "requirements_txt": {
        "patterns": ["==", ">=", "~=", "requests", "flask", "django", "numpy", "pandas"],
        "min_matches": 1,
        "reject_html": True,
    },
    "gemfile": {
        "patterns": ["source ", "gem ", "ruby ", "group :"],
        "min_matches": 1,
        "reject_html": True,
    },
    "pom_xml": {
        "patterns": ["<project", "<groupId>", "<artifactId>", "<version>", "<dependency>"],
        "min_matches": 2,
        "reject_html": True,
    },
    "composer_json": {
        "patterns": ['"require":', '"autoload":', '"name":', '"type":'],
        "min_matches": 1,
        "reject_html": True,
    },
    "go_mod": {
        "patterns": ["module ", "go ", "require (", "require "],
        "min_matches": 1,
        "reject_html": True,
    },
    # Backup files
    "sql_dump": {
        "patterns": ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "ALTER TABLE", "-- MySQL", "-- PostgreSQL", "PGDMP"],
        "min_matches": 1,
        "reject_html": True,
    },
    "archive": {
        "content_type": ["application/zip", "application/x-tar", "application/gzip", "application/x-gzip"],
        "reject_html": True,
    },
    # Kubernetes
    "kubernetes_api": {
        "patterns": ['"kind":', '"apiVersion":', '"metadata":', '"items":', '"kubernetes"'],
        "min_matches": 2,
        "reject_html": True,
    },
}

# HTML indicators (content that's clearly a webpage, not the target file)
HTML_INDICATORS = [
    "<!doctype html", "<html", "<head>", "<body>", "<script", "<div",
    "<meta charset", "<!DOCTYPE", "<title>", "</html>"
]


def validate_content_type(
    body: str,
    content_type: str,
    expected_type: str
) -> tuple[bool, str]:
    """
    Validate that response content matches expected file type.

    Args:
        body: Response body content
        content_type: HTTP Content-Type header
        expected_type: Key from CONTENT_SIGNATURES

    Returns:
        (is_valid, reason)
    """
    if not body:
        return False, "empty_response"

    body_lower = body.lower()[:5000]  # Only check first 5KB

    # Get signature rules
    sig = CONTENT_SIGNATURES.get(expected_type, {})

    # Check if content looks like HTML (false positive indicator)
    if sig.get("reject_html", True):
        html_matches = sum(1 for ind in HTML_INDICATORS if ind.lower() in body_lower)
        if html_matches >= 2:
            return False, "html_content_detected"

    # Check content type if specified
    expected_content_types = sig.get("content_type", [])
    if expected_content_types:
        ct_lower = content_type.lower()
        if any(ect in ct_lower for ect in expected_content_types):
            return True, "content_type_match"
        return False, "content_type_mismatch"

    # Check pattern matches
    patterns = sig.get("patterns", [])
    min_matches = sig.get("min_matches", 1)

    if patterns:
        matches = sum(1 for p in patterns if p.lower() in body_lower)
        if matches >= min_matches:
            return True, "pattern_match"
        return False, "pattern_mismatch"

    # No validation rules - assume valid
    return True, "no_validation_rules"


def is_html_error_page(body: str) -> bool:
    """
    Check if response body looks like an HTML error page rather than actual content.

    Returns True if body appears to be an error page.
    """
    if not body:
        return False

    body_lower = body.lower()[:3000]

    # Check for HTML structure
    has_html = any(ind.lower() in body_lower for ind in HTML_INDICATORS[:5])
    if not has_html:
        return False

    # Check for error indicators
    error_indicators = [
        "404", "not found", "page not found", "file not found",
        "does not exist", "cannot be found", "error", "forbidden",
        "access denied", "unauthorized", "no such", "invalid",
        "sorry, we couldn't find", "page doesn't exist",
        "resource not found", "the requested url",
    ]

    return any(ind in body_lower for ind in error_indicators)


# =============================================================================
# HOMEPAGE COMPARISON - Detect catch-all routing by comparing to homepage
# =============================================================================

async def fetch_homepage_hash(base_url: str, timeout: int = 10) -> str | None:
    """
    Fetch the homepage and return a normalized content hash.

    Used to detect catch-all routing where all paths return the same homepage.
    """
    status, body, _ = await _fetch_url_simple(base_url, timeout)
    if status == 200 and body:
        return _compute_content_hash(body)
    return None


def is_same_as_homepage(body: str, homepage_hash: str | None) -> bool:
    """
    Check if response body matches the homepage content hash.

    Returns True if the body is essentially the same as the homepage,
    indicating a catch-all route.
    """
    if not homepage_hash or not body:
        return False
    return _compute_content_hash(body) == homepage_hash


# =============================================================================
# ADAPTIVE RATE LIMITER - Adjust rate based on target responses
# =============================================================================

class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts requests-per-second based on target responses.

    Features:
    - Backs off on 429 (rate limited) or 503 responses
    - Slows down on server errors (5xx)
    - Gradually speeds up on successful responses
    - Provides async acquire() method for use in rate-limited loops

    Usage:
        limiter = AdaptiveRateLimiter(initial_rps=20)
        async for item in items:
            await limiter.acquire(last_status_code)
            response = await fetch(item)
            last_status_code = response.status
    """

    def __init__(
        self,
        initial_rps: int = 20,
        min_rps: int = 1,
        max_rps: int = 100,
        backoff_factor: float = 0.5,
        speedup_threshold: int = 20,
        speedup_increment: int = 5,
    ):
        """
        Initialize the adaptive rate limiter.

        Args:
            initial_rps: Starting requests per second
            min_rps: Minimum RPS (floor)
            max_rps: Maximum RPS (ceiling)
            backoff_factor: Multiplier when backing off (0.5 = halve rate)
            speedup_threshold: Consecutive successes before speeding up
            speedup_increment: RPS increase when speeding up
        """
        self.rps = initial_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.backoff_factor = backoff_factor
        self.speedup_threshold = speedup_threshold
        self.speedup_increment = speedup_increment

        self._consecutive_errors = 0
        self._consecutive_success = 0
        self._total_requests = 0
        self._rate_limited_count = 0
        self._last_adjustment = "initial"

    async def acquire(self, last_status_code: int | None = None) -> None:
        """
        Acquire a rate limit slot, adjusting rate based on the last response.

        Args:
            last_status_code: HTTP status code of the previous request (None for first request)
        """
        self._total_requests += 1

        if last_status_code is not None:
            await self._adjust_rate(last_status_code)

        # Wait based on current rate
        if self.rps > 0:
            await asyncio.sleep(1.0 / self.rps)

    async def _adjust_rate(self, status_code: int) -> None:
        """Adjust rate based on response status code."""
        if status_code == 429:
            # Rate limited - aggressive backoff
            self.rps = max(self.min_rps, int(self.rps * self.backoff_factor))
            self._consecutive_errors += 1
            self._consecutive_success = 0
            self._rate_limited_count += 1
            self._last_adjustment = "rate_limited"
            # Extra delay on rate limit
            await asyncio.sleep(5)

        elif status_code == 503:
            # Service unavailable - moderate backoff
            self.rps = max(self.min_rps, int(self.rps * 0.7))
            self._consecutive_errors += 1
            self._consecutive_success = 0
            self._last_adjustment = "service_unavailable"
            await asyncio.sleep(3)

        elif status_code >= 500:
            # Other server errors - slight slowdown
            self.rps = max(self.min_rps, self.rps - 5)
            self._consecutive_errors += 1
            self._consecutive_success = 0
            self._last_adjustment = "server_error"

        elif 200 <= status_code < 400:
            # Success - track for potential speedup
            self._consecutive_errors = 0
            self._consecutive_success += 1

            if self._consecutive_success >= self.speedup_threshold:
                self.rps = min(self.max_rps, self.rps + self.speedup_increment)
                self._consecutive_success = 0
                self._last_adjustment = "speedup"

    def get_current_rps(self) -> int:
        """Get current requests per second."""
        return self.rps

    def get_stats(self) -> dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            "current_rps": self.rps,
            "total_requests": self._total_requests,
            "rate_limited_count": self._rate_limited_count,
            "consecutive_errors": self._consecutive_errors,
            "consecutive_success": self._consecutive_success,
            "last_adjustment": self._last_adjustment,
        }

    def reset(self, rps: int | None = None) -> None:
        """Reset rate limiter state."""
        if rps is not None:
            self.rps = rps
        self._consecutive_errors = 0
        self._consecutive_success = 0
        self._last_adjustment = "reset"


# Global rate limiter instance for shared use across modules
_global_rate_limiter: AdaptiveRateLimiter | None = None


def get_adaptive_rate_limiter(initial_rps: int = 20) -> AdaptiveRateLimiter:
    """
    Get the global adaptive rate limiter instance.

    Creates a new instance if one doesn't exist or resets the existing one.
    """
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = AdaptiveRateLimiter(initial_rps=initial_rps)
    return _global_rate_limiter


def create_rate_limiter(initial_rps: int = 20, **kwargs) -> AdaptiveRateLimiter:
    """Create a new adaptive rate limiter instance (not shared)."""
    return AdaptiveRateLimiter(initial_rps=initial_rps, **kwargs)
