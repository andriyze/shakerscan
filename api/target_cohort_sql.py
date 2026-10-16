"""Target cohorts in SQL, equal to ``asset_cohorts.target_cohort`` for every targets row.

The cohort a target row shows (``_public_target_row``, ``/exposure/assets``) is computed in Python:
the operator's ``metadata.cohort``, else a recognised ``metadata.environment``, else ``internal``
for a private/local host, else ``unclassified``. Lists that filter or summarise by cohort over
every target (``/targets/grouped``, ``/timeline``, the dashboard's recent scans) cannot read every
row into Python, so the same decision is made in SQL:

* The metadata part is plain JSON logic, written here to match Python's truthiness, ``strip``,
  ``lower`` and the ``development``/``test`` -> ``lab`` mapping.
* The host part (``target_exposure_class``: URL parsing and the ``ipaddress`` special-purpose
  registries of the running Python) is not re-implemented. It is a pure function of the URL, so
  its result is kept in ``target_url_classes``, keyed by a hash of the URL and the classifier
  version, and filled by Python for any URL not seen yet (``fill_url_classes``) before a query
  that needs it. A URL the cache has no row for reads as not internal; ``fill_url_classes`` is
  what makes the answer exact.

``COHORT_VIEWS`` are the dashboard's selections (``operational`` = production, staging and
unclassified; ``non_operational`` = lab, demo, calibration and internal; or one cohort).
"""
from __future__ import annotations

import sys
from typing import Any, Iterable, Mapping, Sequence

try:
    from asset_cohorts import TARGET_COHORTS, target_cohort, target_exposure_class
except ModuleNotFoundError:  # package import layout
    from .asset_cohorts import TARGET_COHORTS, target_cohort, target_exposure_class

CLASSIFIER_VERSION = f"exposure-class/v1:py{sys.version_info.major}.{sys.version_info.minor}"

COHORT_VIEWS: dict[str, tuple[str, ...]] = {
    "operational": ("production", "staging", "unclassified"),
    "non_operational": ("lab", "demo", "calibration", "internal"),
    **{name: (name,) for name in (*TARGET_COHORTS, "unclassified")},
}
COHORT_VIEW_PATTERN = "^(operational|non_operational|production|staging|lab|demo|calibration|internal|unclassified|all)$"

# The cache table ``target_url_classes`` is created with the summary tables (targets/scale_summary.py).


def url_hash_sql(url_expr: str) -> str:
    return f"encode(sha256(convert_to(COALESCE({url_expr}, ''), 'UTF8')), 'hex')"


# Python's ``str.strip()`` set (``str.isspace``), spelled as code points so SQL strips the same.
_PY_WHITESPACE = "".join(f"\\u{ord(c):04x}" for c in map(chr, range(0x10000)) if c.isspace())


def _strip_lower(text_expr: str) -> str:
    return (f"lower(regexp_replace({text_expr}, '^[{_PY_WHITESPACE}]+|[{_PY_WHITESPACE}]+$', '', 'g'))")


def _truthy(value_expr: str) -> str:
    """Python truthiness of a JSON value (``None``, ``False``, ``0``, ``""``, ``[]``, ``{}`` are falsy)."""
    return (f"({value_expr} IS NOT NULL AND jsonb_typeof({value_expr}) <> 'null' "
            f"AND {value_expr} NOT IN ('false'::jsonb, '\"\"'::jsonb, '[]'::jsonb, '{{}}'::jsonb) "
            f"AND NOT (jsonb_typeof({value_expr}) = 'number' AND ({value_expr})::text::numeric = 0))")


def _normalized(text_expr: str) -> str:
    stripped = _strip_lower(text_expr)
    return f"(CASE {stripped} WHEN 'development' THEN 'lab' WHEN 'test' THEN 'lab' ELSE {stripped} END)"


def url_is_internal_sql(url_expr: str, version_ref: str) -> str:
    """Whether the cached host class of ``url_expr`` is internal (``version_ref``: the bound
    ``CLASSIFIER_VERSION``). A primary-key probe per row."""
    return (f"EXISTS (SELECT 1 FROM target_url_classes tuc WHERE tuc.url_hash = {url_hash_sql(url_expr)} "
            f"AND tuc.classifier_version = {version_ref} AND tuc.exposure_class = 'internal')")


def cohort_sql(metadata_expr: str, internal_expr: str) -> str:
    """The cohort of a row: ``metadata_expr`` is its metadata JSON, ``internal_expr`` whether its
    URL's host is internal (``url_is_internal_sql``)."""
    meta = f"(CASE WHEN jsonb_typeof({metadata_expr}) = 'object' THEN {metadata_expr} ELSE '{{}}'::jsonb END)"
    explicit = f"({meta} -> 'cohort')"
    environment = f"({meta} -> 'environment')"
    allowed = ", ".join(f"'{name}'" for name in (*TARGET_COHORTS, "unclassified"))
    cohorts = ", ".join(f"'{name}'" for name in TARGET_COHORTS)
    explicit_text = f"({meta} ->> 'cohort')"
    environment_text = f"(CASE WHEN {_truthy(environment)} THEN {meta} ->> 'environment' ELSE '' END)"
    return f"""(CASE
        WHEN {_truthy(explicit)} THEN
            (CASE WHEN {_normalized(explicit_text)} IN ({allowed}) THEN {_normalized(explicit_text)}
                  ELSE 'unclassified' END)
        WHEN {_strip_lower(environment_text)} IN ({cohorts}, 'development', 'test') THEN {_normalized(environment_text)}
        WHEN {internal_expr} THEN 'internal'
        ELSE 'unclassified' END)"""


def target_cohort_sql(alias: str, version_ref: str) -> str:
    """The cohort of the targets row ``alias``."""
    return cohort_sql(f"{alias}.metadata_json", url_is_internal_sql(f"{alias}.url", version_ref))


def cohort_filter_sql(alias: str, cohorts: Sequence[str], params: Any) -> str:
    """``alias`` (a targets row) is in one of ``cohorts``; ``params`` is a ``SqlParams``."""
    version_ref = params.add(CLASSIFIER_VERSION)
    return f"{target_cohort_sql(alias, version_ref)} = ANY({params.add(list(cohorts))}::text[])"


def view_cohorts(view: str | None) -> tuple[str, ...] | None:
    """The cohorts a view selects; ``None`` for ``all`` (or no view)."""
    if not view or view == "all":
        return None
    if view not in COHORT_VIEWS:
        raise ValueError(f"unknown cohort view {view!r}")
    return COHORT_VIEWS[view]


async def fill_url_classes(conn: Any, *, urls: Iterable[str] | None = None) -> int:
    """Classify, in Python, every target URL (or each of ``urls``) the cache has not seen."""
    if urls is None:
        missing = await conn.fetch(
            f"""SELECT DISTINCT t.url FROM targets t
                WHERE NOT EXISTS (SELECT 1 FROM target_url_classes c
                                  WHERE c.url_hash = {url_hash_sql('t.url')} AND c.classifier_version = $1)""",
            CLASSIFIER_VERSION,
        )
        values = [row["url"] or "" for row in missing]
    else:
        wanted = sorted({str(url or "") for url in urls})
        if not wanted:
            return 0
        missing = await conn.fetch(
            f"""SELECT u.url FROM unnest($2::text[]) AS u(url)
                WHERE NOT EXISTS (SELECT 1 FROM target_url_classes c
                                  WHERE c.url_hash = {url_hash_sql('u.url')} AND c.classifier_version = $1)""",
            CLASSIFIER_VERSION, wanted,
        )
        values = [row["url"] or "" for row in missing]
    if not values:
        return 0
    classes = sorted({(url, target_exposure_class(url)) for url in values})
    # In hash order, so concurrent fills take row locks in one order (no deadlock).
    await conn.execute(
        f"""INSERT INTO target_url_classes(url_hash, exposure_class, classifier_version)
            SELECT {url_hash_sql('v.url')}, v.exposure_class, $3
            FROM unnest($1::text[], $2::text[]) AS v(url, exposure_class)
            ORDER BY 1
            ON CONFLICT (url_hash) DO UPDATE
               SET exposure_class = EXCLUDED.exposure_class, classifier_version = EXCLUDED.classifier_version""",
        [url for url, _ in classes], [cls for _, cls in classes], CLASSIFIER_VERSION,
    )
    return len(classes)


async def cohorts_for_targets(conn: Any, target_ids: Sequence[Any]) -> dict[str, str]:
    """The exact (Python) cohort of each target id, from one bounded read."""
    ids = sorted({str(value) for value in target_ids if value})
    if not ids:
        return {}
    rows = await conn.fetch(
        """SELECT id, url, name, discovery_source,
                  CASE WHEN jsonb_typeof(metadata_json) = 'object'
                       THEN jsonb_strip_nulls(jsonb_build_object(
                                'cohort', metadata_json -> 'cohort',
                                'environment', metadata_json -> 'environment'))
                       ELSE '{}'::jsonb END AS metadata
           FROM targets WHERE id = ANY($1::uuid[])""",
        ids,
    )
    result: dict[str, str] = {}
    for row in rows:
        metadata = row["metadata"]
        if isinstance(metadata, str):
            import json
            metadata = json.loads(metadata)
        result[str(row["id"])] = target_cohort(
            url=row["url"], name=row["name"], discovery_source=row["discovery_source"],
            metadata=metadata if isinstance(metadata, Mapping) else {},
        )
    return result


async def cohorts_for_ai_targets(conn: Any, ai_target_ids: Sequence[Any]) -> dict[str, str]:
    """The exact cohort of each AI target, as ``/exposure/assets`` computes it."""
    ids = sorted({str(value) for value in ai_target_ids if value})
    if not ids:
        return {}
    rows = await conn.fetch(
        """SELECT id, endpoint_url, name,
                  CASE WHEN jsonb_typeof(metadata_json) = 'object'
                       THEN jsonb_strip_nulls(jsonb_build_object(
                                'cohort', metadata_json -> 'cohort',
                                'environment', metadata_json -> 'environment'))
                       ELSE '{}'::jsonb END AS metadata
           FROM ai_targets WHERE id = ANY($1::uuid[])""",
        ids,
    )
    result: dict[str, str] = {}
    for row in rows:
        metadata = row["metadata"]
        if isinstance(metadata, str):
            import json
            metadata = json.loads(metadata)
        url = row["endpoint_url"]
        result[str(row["id"])] = target_cohort(
            url=url, name=row["name"], discovery_source="ai_gate",
            metadata=metadata if isinstance(metadata, Mapping) else {},
            exposure_class=target_exposure_class(url),
        )
    return result


async def row_cohorts(conn: Any, rows: Sequence[Mapping[str, Any]], *, target_key: str = "target_id",
                      ai_target_key: str = "ai_target_id", url_key: str = "target_url") -> list[str | None]:
    """The cohort of each row's subject: its target, else its AI target, else its URL's host;
    ``None`` for a row that names none of them (a global event)."""
    targets = await cohorts_for_targets(conn, [row.get(target_key) for row in rows])
    ai_targets = await cohorts_for_ai_targets(conn, [row.get(ai_target_key) for row in rows if not row.get(target_key)])
    labels: list[str | None] = []
    for row in rows:
        target_id, ai_target_id, url = row.get(target_key), row.get(ai_target_key), row.get(url_key)
        if target_id:
            labels.append(targets.get(str(target_id), url_only_cohort(url) if url else "unclassified"))
        elif ai_target_id:
            labels.append(ai_targets.get(str(ai_target_id), url_only_cohort(url) if url else "unclassified"))
        elif url:
            labels.append(url_only_cohort(url))
        else:
            labels.append(None)
    return labels


def url_only_cohort(url: Any) -> str:
    """The cohort of a row that names a URL but no target: the host decides, metadata is unknown."""
    return target_cohort(url=url, metadata={})


__all__ = [
    "CLASSIFIER_VERSION", "COHORT_VIEWS", "COHORT_VIEW_PATTERN",
    "cohort_filter_sql", "cohort_sql", "cohorts_for_ai_targets", "cohorts_for_targets", "row_cohorts", "fill_url_classes", "target_cohort_sql",
    "url_is_internal_sql",
    "url_hash_sql", "url_only_cohort", "view_cohorts",
]
