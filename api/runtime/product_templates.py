"""The template checks of a recognised product, run by a web Hunt's ``templates.scan``.

A Hunt's ``templates.scan`` otherwise runs only the reviewed passive pack (six GET templates).
Once discovery recognises a product on the target (``hunt/auto_discovery.py``: Jenkins, Jupyter,
Ray, a Docker daemon, a kubelet ...), the engine runs that product's own templates from the
pinned bundle: ``templates.scan`` with ``product`` set to the product's key.

Selection (on the worker, which holds the bundle; ``scan/nuclei_template_index.py`` classifies
every template):

* the templates carrying one of the product's tags;
* never an ``intrusive`` template, one that requests a never-requested path, one that needs an
  out-of-band interaction (a Hunt runs nuclei with ``-no-interactsh``, so it could never match),
  or one without a static request bound (a ``flow``/``code``/``javascript`` step, a
  ``self-contained`` template that requests its own URLs);
* never a template that tries logins (``default-login`` and other credential-level templates):
  a login attempt can lock the account it tries, and the sweep tries default credentials itself
  under the default-credential module's attempt cap, pacing and lockout stop;
* ``product_checks: read_only`` (the default) runs the templates whose every request is a GET or
  HEAD and that send no attack input. ``state_changing`` runs the rest: non-GET templates and
  exploit-class checks (rce, lfi, sqli, ssti, xxe, ssrf, deserialization, code injection). It
  needs the Hunt's active testing and state-changing permissions, and every request it may send is
  held and settled as a verifier write (``verifier_write_requests``), the ceiling a body test of
  ``sqli.verify``/``xss.verify`` uses, so the engine's checks never spend the planner's own writes.

A product's selection is cut, in template-id order, into windows whose summed request bounds fit
one call's hold; ``product_window`` names the window. Admission reserves the fixed hold of the
call's kind (the API image has no bundle), and the worker refuses a window whose bound exceeds
it, so the run can never need more than was reserved.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

# Product key (hunt/auto_discovery.py PRODUCTS) -> the bundle tags of its templates.
PRODUCT_TEMPLATE_TAGS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "jenkins": ("jenkins",),
    "jupyter": ("jupyter", "jupyterlab"),
    "ray": ("ray",),
    "mlflow": ("mlflow",),
    "langflow": ("langflow",),
    "flowise": ("flowise",),
    "comfyui": ("comfyui",),
    "ollama": ("ollama",),
    "tomcat": ("tomcat",),
    "phpmyadmin": ("phpmyadmin",),
    "wordpress": ("wordpress",),
    "drupal": ("drupal",),
    "joomla": ("joomla",),
    "laravel": ("laravel",),
    "spring": ("springboot", "spring", "spring-boot"),
    "jolokia": ("jolokia",),
    "docker_api": ("docker",),
    "container_registry": ("registry",),
    "kubelet": ("kubelet", "kubernetes"),
    "kubernetes": ("kubernetes", "k8s"),
    "etcd": ("etcd",),
    "consul": ("consul",),
    "elasticsearch": ("elasticsearch", "elastic"),
    "grafana": ("grafana",),
    "gitlab": ("gitlab",),
    "prometheus": ("prometheus",),
    "solr": ("solr",),
    "n8n": ("n8n",),
    "exchange": ("exchange",),
    "nextjs": ("nextjs", "next-js"),
})
PRODUCT_KEYS: tuple[str, ...] = tuple(sorted(PRODUCT_TEMPLATE_TAGS))

# Where a product is commonly served under a path of its own. A product found there is checked
# there as well as at the root: its templates address the product from ``{{BaseURL}}``.
PRODUCT_MOUNTS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "jenkins": ("/jenkins/",),
    "phpmyadmin": ("/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/dbadmin/", "/myadmin/"),
    "ollama": ("/ollama/",),
    "solr": ("/solr/",),
    "gitlab": ("/gitlab/",),
    "grafana": ("/grafana/",),
})

PRODUCT_CHECKS = ("read_only", "state_changing")
# One call's hold, sized from the pinned bundle's request bounds (each checked against the
# requests nuclei actually sent, run by run): every product's read-only selection but WordPress
# fits one window (the largest, GitLab, bounds 120 requests, one template alone 100; Spring 103),
# and WordPress's 648 GET templates (bound 1,003) take three. Every state-changing selection but
# WordPress fits one window (the largest, Joomla's 131 extension checks, bounds 132); WordPress's
# 488 take six. A window runs well inside the wall at nuclei's 10 requests per second.
# tests/test_product_templates.py pins the window plan to the bundle in the scanner image.
READ_ONLY_WINDOW_REQUESTS = 480
STATE_CHANGING_WINDOW_REQUESTS = 160
# A window runs at nuclei's rate ceiling (10 requests per second) with a single template in
# flight per request batch; a whole read-only window needs under a minute at full rate and the
# wall leaves room for slow answers (5 s request timeout) and a degraded target's lower pace.
PRODUCT_WALL_SECONDS = 300
MAX_PRODUCT_WINDOW = 63
# Products whose selection needs more than one window at these holds, in the pinned bundle
# (tests/test_product_templates.py recomputes it in the scanner image). Every other selection
# runs in one window. The sweep runs each window; the API image has no bundle to count them.
PRODUCT_WINDOW_COUNTS: Mapping[tuple[str, str], int] = MappingProxyType({
    ("wordpress", "read_only"): 3,
    ("wordpress", "state_changing"): 6,
})


def product_window_count(product: str, checks: str) -> int:
    return PRODUCT_WINDOW_COUNTS.get((product, checks), 1)


def product_hold(checks: str) -> dict[str, int]:
    """What admission reserves for one product-template call (no bundle needed)."""
    if checks == "state_changing":
        return {"http_requests": STATE_CHANGING_WINDOW_REQUESTS,
                "verifier_write_requests": STATE_CHANGING_WINDOW_REQUESTS,
                "tool_wall_seconds": PRODUCT_WALL_SECONDS}
    return {"http_requests": READ_ONLY_WINDOW_REQUESTS, "tool_wall_seconds": PRODUCT_WALL_SECONDS}


def product_request(capability_input: Mapping[str, Any]) -> tuple[str, str, int] | None:
    """``(product, checks, window)`` of a product-template call, or None for any other call."""
    product = capability_input.get("product")
    if not product:
        return None
    product = str(product)
    if product not in PRODUCT_TEMPLATE_TAGS:
        raise ValueError(f"no template checks for product {product!r}")
    checks = str(capability_input.get("product_checks") or "read_only")
    if checks not in PRODUCT_CHECKS:
        raise ValueError(f"product_checks must be one of {PRODUCT_CHECKS}")
    window = capability_input.get("product_window", 0)
    if isinstance(window, bool) or not isinstance(window, int) or not 0 <= window <= MAX_PRODUCT_WINDOW:
        raise ValueError("product_window is out of range")
    return product, checks, window


@dataclass(frozen=True)
class ProductWindow:
    """One window of a product's selection, or why it cannot run."""

    product: str
    checks: str
    window: int
    windows: int
    template_ids: tuple[str, ...]
    request_upper_bound: int
    skip_reason: str | None
    counts: Mapping[str, int]

    def telemetry(self) -> dict[str, Any]:
        return {"product": self.product, "checks": self.checks, "window": self.window,
                "windows": self.windows, "selected": len(self.template_ids),
                "request_upper_bound": self.request_upper_bound, **dict(self.counts)}


def _excluded(record: Any) -> str | None:
    if record.intrusive:
        return "intrusive"
    if record.never_requested:
        return "never_requested"
    if record.oob:
        return "oob"
    if record.credential_level:
        return "login_attempts"
    if record.max_requests is None:
        return "unbounded"
    return None


def product_windows(index: Any, product: str, checks: str) -> tuple[list[tuple[str, ...]], dict[str, int], list[int]]:
    """A product's eligible templates cut into windows, the exclusion counts and each window's bound."""
    tags = frozenset(PRODUCT_TEMPLATE_TAGS[product])
    limit = STATE_CHANGING_WINDOW_REQUESTS if checks == "state_changing" else READ_ONLY_WINDOW_REQUESTS
    counts: dict[str, int] = {}
    eligible = []
    for record in sorted(index.templates, key=lambda item: item.template_id):
        if not record.tags & tags or record.state_changing != (checks == "state_changing"):
            continue
        reason = _excluded(record)
        if reason is None and record.max_requests > limit:
            reason = "exceeds_window"
        if reason is None and not _valid_id(record.template_id):
            reason = "invalid_id"
        if reason:
            counts[f"excluded_{reason}"] = counts.get(f"excluded_{reason}", 0) + 1
            continue
        eligible.append(record)
    windows: list[tuple[str, ...]] = []
    bounds: list[int] = []
    current: list[str] = []
    used = 0
    for record in eligible:
        if current and used + record.max_requests > limit:
            windows.append(tuple(current))
            bounds.append(used)
            current, used = [], 0
        current.append(record.template_id)
        used += record.max_requests
    if current:
        windows.append(tuple(current))
        bounds.append(used)
    return windows, counts, bounds


def _valid_id(template_id: str) -> bool:
    try:
        from scan.nuclei_template_index import _TEMPLATE_ID_RE
    except ModuleNotFoundError:  # package import in host-side tests
        from ..scan.nuclei_template_index import _TEMPLATE_ID_RE
    return bool(_TEMPLATE_ID_RE.match(template_id))


def resolve_product_window(templates_dir: str, product: str, checks: str, window: int, *,
                           allow_state_changing_http: bool) -> ProductWindow:
    """The templates one product-template call runs, read from the pinned bundle; fails closed."""
    try:
        from scan.nuclei_template_index import _cached_index
    except ModuleNotFoundError:  # package import in host-side tests
        from ..scan.nuclei_template_index import _cached_index

    def skip(reason: str, windows: int = 0, counts: Mapping[str, int] | None = None) -> ProductWindow:
        return ProductWindow(product, checks, window, windows, (), 0, reason, dict(counts or {}))

    if product not in PRODUCT_TEMPLATE_TAGS or checks not in PRODUCT_CHECKS:
        return skip("unknown_product")
    if checks == "state_changing" and not allow_state_changing_http:
        return skip("needs_state_changing_http")
    try:
        index = _cached_index(templates_dir)
    except (FileNotFoundError, RuntimeError, OSError):
        return skip("nuclei_template_index_unavailable")
    windows, counts, bounds = product_windows(index, product, checks)
    if not windows:
        return skip("no_eligible_templates", 0, counts)
    if window >= len(windows):
        return skip("window_past_selection", len(windows), counts)
    return ProductWindow(product, checks, window, len(windows), windows[window], bounds[window], None, counts)


__all__ = [
    "MAX_PRODUCT_WINDOW", "PRODUCT_CHECKS", "PRODUCT_KEYS", "PRODUCT_MOUNTS", "PRODUCT_TEMPLATE_TAGS",
    "PRODUCT_WALL_SECONDS", "ProductWindow", "READ_ONLY_WINDOW_REQUESTS", "STATE_CHANGING_WINDOW_REQUESTS",
    "PRODUCT_WINDOW_COUNTS", "product_hold", "product_request", "product_window_count", "product_windows",
    "resolve_product_window",
]
