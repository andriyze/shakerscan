#!/usr/bin/env python3
"""First-class CLI for canonical ShakerScan V2 workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request
import uuid


MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BYTES = 52 * 1024 * 1024
MAX_DOCUMENT_BYTES = 50 * 1024 * 1024


class CliError(RuntimeError):
    """A safe, user-facing CLI failure."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str = "client_error",
        http_status: int | None = None,
        api_detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.http_status = http_status
        self.api_detail = api_detail

    def public_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "shakerscan-cli-error/v1",
            "error": self.error_type,
            "message": str(self),
        }
        if self.http_status is not None:
            result["http_status"] = self.http_status
        if self.api_detail is not None:
            result["api_detail"] = self.api_detail
        return result


class ApiClient:
    def __init__(self, base_url: str, *, timeout: float = 60.0) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.timeout = timeout
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CliError("the configured ShakerScan API URL is invalid")

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_REQUEST_BYTES:
                raise CliError("request JSON exceeds the 52 MiB CLI limit")
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body, headers=headers, method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_JSON_BYTES + 1)
            message, detail = _safe_api_error(
                raw, fallback=f"API returned HTTP {exc.code}"
            )
            raise CliError(
                message,
                error_type="api_error",
                http_status=exc.code,
                api_detail=detail,
            ) from exc
        except urllib.error.URLError as exc:
            raise CliError(
                f"cannot reach ShakerScan API: {exc.reason}",
                error_type="network_error",
            ) from exc
        if len(raw) > MAX_JSON_BYTES:
            raise CliError("API response exceeds the 4 MiB CLI limit")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CliError("ShakerScan API returned invalid JSON") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> Any:
        return self.request(
            "POST", path, payload=payload, idempotency_key=idempotency_key,
        )

    def download(self, path: str, *, max_bytes: int = MAX_REQUEST_BYTES) -> tuple[bytes, str]:
        request = urllib.request.Request(
            f"{self.base_url}{path}", headers={"Accept": "application/json, application/zip"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(max_bytes + 1)
                content_type = str(response.headers.get("Content-Type") or "")
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_JSON_BYTES + 1)
            message, detail = _safe_api_error(
                raw, fallback=f"API returned HTTP {exc.code}"
            )
            raise CliError(
                message,
                error_type="api_error",
                http_status=exc.code,
                api_detail=detail,
            ) from exc
        except urllib.error.URLError as exc:
            raise CliError(
                f"cannot reach ShakerScan API: {exc.reason}",
                error_type="network_error",
            ) from exc
        if len(raw) > max_bytes:
            raise CliError("evidence export exceeds the 52 MiB CLI limit")
        return raw, content_type


def _safe_api_error(raw: bytes, *, fallback: str) -> tuple[str, Any]:
    try:
        value = json.loads(raw[:MAX_JSON_BYTES])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return fallback, None
    detail = value.get("detail") if isinstance(value, Mapping) else None
    if isinstance(detail, str) and detail.strip():
        message = detail.strip()[:2_000]
        return message, message
    if isinstance(detail, list):
        messages = [
            str(item.get("msg") or "invalid request")
            for item in detail
            if isinstance(item, Mapping)
        ]
        if messages:
            return "; ".join(messages)[:2_000], detail
    if isinstance(detail, Mapping):
        message = str(
            detail.get("message") or detail.get("error") or fallback
        )[:2_000]
        return message, dict(detail)
    return fallback, detail


def _validate_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    key = str(value)
    if not 8 <= len(key) <= 200:
        raise CliError("idempotency key must contain 8 to 200 characters")
    if not key[0].isalnum() or any(
        not (character.isalnum() or character in "_.:-") for character in key
    ):
        raise CliError(
            "idempotency key must start with an alphanumeric character and use only "
            "letters, numbers, underscore, dot, colon, or hyphen"
        )
    return key


def _content_idempotency_key(*values: Any) -> str:
    material = json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return "cli-" + hashlib.sha256(material).hexdigest()


def _read_json(path: str | None, *, default: Any) -> Any:
    if path is None:
        return default
    if path == "-":
        raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    else:
        file_path = Path(path).expanduser()
        try:
            if file_path.stat().st_size > MAX_JSON_BYTES:
                raise CliError("input JSON exceeds the 4 MiB CLI limit")
            raw = file_path.read_bytes()
        except OSError as exc:
            raise CliError(f"cannot read JSON input: {exc}") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise CliError("input JSON exceeds the 4 MiB CLI limit")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CliError("input is not valid UTF-8 JSON") from exc


def _pairs(values: Sequence[str], *, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        name, separator, value = str(raw).partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name or not value:
            raise CliError(f"{label} must use NAME=VALUE")
        if name in result:
            raise CliError(f"duplicate {label} name: {name}")
        result[name] = value
    return result


def _openapi_schema(client: ApiClient, name: str) -> Mapping[str, Any]:
    contract = client.get("/openapi.json")
    try:
        schema = contract["components"]["schemas"][name]
    except (KeyError, TypeError) as exc:
        raise CliError(f"running server does not publish the {name} contract") from exc
    if not isinstance(schema, Mapping):
        raise CliError(f"running server returned an invalid {name} contract")
    return schema


def _validate_schema_object(
    value: Any, schema: Mapping[str, Any], *, label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CliError(f"{label} must be one JSON object")
    properties = set((schema.get("properties") or {}).keys())
    unknown = sorted(set(value) - properties)
    if unknown and schema.get("additionalProperties") is False:
        raise CliError(f"{label} contains unsupported fields: {', '.join(unknown)}")
    missing = sorted(set(schema.get("required") or ()) - set(value))
    if missing:
        raise CliError(f"{label} is missing required fields: {', '.join(missing)}")
    return value


def _read_document(path: str) -> Any:
    file_path = Path(path).expanduser()
    try:
        if file_path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise CliError("request collection document exceeds 50 MiB")
        raw = file_path.read_bytes()
    except OSError as exc:
        raise CliError(f"cannot read request collection document: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CliError("request collection document must be UTF-8") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _hunt_start_payload(args: argparse.Namespace, contract: Mapping[str, Any]) -> dict[str, Any]:
    if args.request:
        value = _read_json(args.request, default={})
        if not isinstance(value, dict):
            raise CliError("Hunt start request must be one JSON object")
        if value.get("schema_version") != contract.get("schema_version"):
            raise CliError("Hunt request schema_version does not match the server contract")
        return value

    target_kinds = {str(item) for item in contract.get("target_kinds") or ()}
    if not args.target_id:
        raise CliError("--target-id is required unless --request is used")
    if not args.target_kind:
        raise CliError("--target-kind is required unless --request is used")
    if args.target_kind not in target_kinds:
        raise CliError("target kind is not supported by the running server")
    profiles = contract.get("budget_profiles") or {}
    if args.budget_profile not in profiles:
        raise CliError("budget profile is not supported by the running server")

    dimensions = {
        str(item.get("name")): item
        for item in contract.get("budget_dimensions") or ()
        if isinstance(item, Mapping) and item.get("name")
    }
    budgets: dict[str, int] = {}
    for name, raw_value in _pairs(args.budget, label="budget").items():
        if name not in dimensions:
            raise CliError(f"budget dimension is not supported by the server: {name}")
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise CliError(f"budget {name} must be an integer") from exc
        minimum = int(dimensions[name].get("minimum") or 0)
        if value < minimum:
            raise CliError(f"budget {name} must be at least {minimum}")
        profile_max = int((profiles.get(args.budget_profile) or {}).get(name) or 0)
        if value > profile_max:
            raise CliError(
                f"budget {name} exceeds the server's {args.budget_profile} ceiling"
            )
        budgets[name] = value

    return {
        "schema_version": str(contract["schema_version"]),
        "target_id": args.target_id,
        "target_kind": args.target_kind,
        "goal": args.goal,
        "budget_profile": args.budget_profile,
        "policy": {
            "active_testing": bool(args.active_testing),
            "allow_state_changing_http": bool(args.allow_state_changing_http),
            "network_discovery": bool(args.network_discovery),
            "allow_oob_interactions": bool(args.allow_oob_interactions),
            "authorization_confirmed": bool(args.authorized),
            "approval_receipt_id": args.approval_receipt_id,
            "scope_receipt_id": args.scope_receipt_id,
        },
        "budgets": budgets,
        "credential_refs": _pairs(args.credential_ref, label="credential reference"),
        "capabilities": list(dict.fromkeys(args.capability)),
        "request_collection_ids": list(dict.fromkeys(args.collection_id)),
    }


def _run_hunt(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.hunt_command == "start":
        contract = client.get("/hunts/contract")
        if not isinstance(contract, Mapping):
            raise CliError("running server returned an invalid Hunt contract")
        return client.post(
            "/hunts",
            _hunt_start_payload(args, contract),
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.hunt_command == "call":
        run = client.get(f"/hunts/{urllib.parse.quote(args.hunt_id, safe='')}")
        if not isinstance(run, Mapping):
            raise CliError("running server returned an invalid Hunt record")
        capability_names = {
            str(item.get("name") if isinstance(item, Mapping) else item)
            for item in run.get("capabilities") or ()
        }
        if args.capability_name not in capability_names:
            raise CliError("capability is not present in the server-returned Hunt manifest")
        inputs = _read_json(args.input, default={})
        if not isinstance(inputs, dict):
            raise CliError("Hunt capability input must be one JSON object")
        key = _validate_idempotency_key(args.idempotency_key) or _content_idempotency_key(
            args.hunt_id, args.capability_name, inputs,
        )
        response = client.post(
            "/hunts/{}/capabilities/{}".format(
                urllib.parse.quote(args.hunt_id, safe=""),
                urllib.parse.quote(args.capability_name, safe=""),
            ),
            {"idempotency_key": key, "input": inputs},
        )
        return {"idempotency_key": key, "response": response}
    raise CliError("unknown Hunt command")


def _run_credentials(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.credentials_command == "create":
        schema = _openapi_schema(client, "CredentialProfileCreate")
        payload = _validate_schema_object(
            _read_json(args.request, default={}), schema,
            label="credential create request",
        )
        return client.post(
            "/credential-profiles",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.credentials_command == "rotate":
        schema = _openapi_schema(client, "CredentialProfileRotate")
        payload = _validate_schema_object(
            _read_json(args.request, default={}), schema,
            label="credential rotation request",
        )
        profile_id = urllib.parse.quote(args.profile_id, safe="")
        return client.post(
            f"/credential-profiles/{profile_id}/rotate",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.credentials_command == "test":
        profile_id = urllib.parse.quote(args.profile_id, safe="")
        result = client.get(f"/credential-profiles/{profile_id}")
        profile = result.get("profile") if isinstance(result, Mapping) else None
        if not isinstance(profile, Mapping):
            raise CliError("running server returned invalid credential metadata")
        checks = {
            "active": profile.get("status") == "active",
            "execution_compatible": profile.get("execution_compatible") is True,
            "storage_encrypted": profile.get("storage_encrypted") is True,
            "encryption_available": profile.get("encryption_available") is True,
            "target_bound": bool(profile.get("target_id") and profile.get("target_kind")),
        }
        if args.capability:
            allowed = {str(item) for item in profile.get("allowed_capabilities") or ()}
            checks["capability_allowed"] = not allowed or args.capability in allowed
        return {
            "schema_version": "credential-admission-test/v1",
            "profile_id": str(profile.get("profile_id") or args.profile_id),
            "test_mode": "metadata_admission",
            "passed": all(checks.values()),
            "checks": checks,
            "profile": profile,
            "note": (
                "This content-free check validates storage, lifecycle, target binding, and "
                "capability admission. Exercise the profile against its target through a "
                "target-bound Hunt capability."
            ),
        }
    raise CliError("unknown credentials command")


def _collection_upload_payload(
    args: argparse.Namespace, client: ApiClient,
) -> dict[str, Any]:
    schema = _openapi_schema(client, "RequestCollectionCreate")
    if args.request:
        return _validate_schema_object(
            _read_json(args.request, default={}), schema,
            label="request collection upload",
        )
    if not args.target_id or not args.document:
        raise CliError("collections upload requires --target-id and a document")
    payload: dict[str, Any] = {
        "target_id": args.target_id,
        "document": _read_document(args.document),
        "format": args.format,
        "import_limit": args.import_limit,
        "max_document_bytes": MAX_DOCUMENT_BYTES,
    }
    for name in ("name", "environment_name", "base_url"):
        value = getattr(args, name)
        if value is not None:
            payload[name] = value
    if args.environment:
        payload["environment"] = _read_document(args.environment)
    return _validate_schema_object(payload, schema, label="request collection upload")


def _run_collections(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.collections_command == "upload":
        return client.post(
            "/request-collections",
            _collection_upload_payload(args, client),
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    collection_id = urllib.parse.quote(args.collection_id, safe="")
    if args.collections_command == "bind":
        schema = _openapi_schema(client, "RequestCollectionBindingUpsert")
        if args.request:
            payload = _read_json(args.request, default={})
        else:
            payload = {
                "target_kind": args.target_kind,
                "target_id": args.target_id,
                "allowed_origins": list(dict.fromkeys(args.allowed_origin)),
            }
            if args.environment_id:
                payload["environment_id"] = args.environment_id
        payload = _validate_schema_object(
            payload, schema, label="request collection binding",
        )
        return client.post(
            f"/request-collections/{collection_id}/bindings",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    if args.collections_command == "select":
        schema = _openapi_schema(client, "RequestCollectionSelect")
        if args.request:
            payload = _read_json(args.request, default={})
        else:
            payload = {
                "request_ids": list(dict.fromkeys(args.request_id)),
                "folders": list(dict.fromkeys(args.folder)),
                "methods": list(dict.fromkeys(method.upper() for method in args.method)),
                "tags": list(dict.fromkeys(args.tag)),
                "safe_methods_only": not args.include_mutating,
                "limit": args.limit,
            }
            if args.path_regex:
                payload["path_regex"] = args.path_regex
        payload = _validate_schema_object(
            payload, schema, label="request collection selection",
        )
        return client.post(
            f"/request-collections/{collection_id}/select",
            payload,
            idempotency_key=_validate_idempotency_key(args.idempotency_key),
        )
    raise CliError("unknown collections command")


def _write_export(path: str, value: bytes, *, force: bool) -> Path:
    output = Path(path).expanduser()
    if output.exists() and not force:
        raise CliError("evidence export output already exists; use --force to replace it")
    temporary: Path | None = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_bytes(value)
        if force:
            temporary.replace(output)
        else:
            os.link(temporary, output)
            temporary.unlink()
    except FileExistsError as exc:
        raise CliError(
            "evidence export output already exists; use --force to replace it"
        ) from exc
    except OSError as exc:
        raise CliError(f"cannot write evidence export: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return output.resolve()


def _run_evidence(args: argparse.Namespace, client: ApiClient) -> Any:
    if args.evidence_command != "export":
        raise CliError("unknown evidence command")
    query: dict[str, str] = {"limit": str(args.limit)}
    for name in ("scan_id", "finding_id", "retention_class"):
        value = getattr(args, name)
        if value:
            query[name] = str(value)
    if args.format == "manifest":
        path = f"/evidence/export-manifest?{urllib.parse.urlencode(query)}"
    else:
        query["format"] = args.format
        query["record_event"] = "true" if args.record_event else "false"
        path = f"/evidence/export-bundle?{urllib.parse.urlencode(query)}"
    raw, content_type = client.download(path)
    if args.format == "zip" and "zip" not in content_type.lower():
        raise CliError("running server did not return the requested evidence zip")
    if args.output:
        output = _write_export(args.output, raw, force=args.force)
        return {
            "schema_version": "evidence-cli-export/v1",
            "format": args.format,
            "output": str(output),
            "bytes": len(raw),
            "content_type": content_type,
        }
    if args.format == "zip":
        raise CliError("zip evidence export requires --output")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CliError("running server returned invalid evidence JSON") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shakerscan",
        description="Canonical ShakerScan V2 command line",
    )
    parser.add_argument("--api-url", required=True, help=argparse.SUPPRESS)
    products = parser.add_subparsers(dest="product", required=True)

    hunt = products.add_parser("hunt", help="Start or drive one canonical Hunt")
    hunt_commands = hunt.add_subparsers(dest="hunt_command", required=True)
    hunt_start = hunt_commands.add_parser("start", help="Start a target-bound Hunt")
    hunt_start.add_argument("--request", metavar="FILE", help="Complete JSON contract; use - for stdin")
    hunt_start.add_argument("--idempotency-key")
    hunt_start.add_argument("--target-id")
    hunt_start.add_argument("--target-kind")
    hunt_start.add_argument("--goal", default="Investigate the authorized target.")
    hunt_start.add_argument("--budget-profile", default="balanced")
    hunt_start.add_argument("--active-testing", action="store_true")
    hunt_start.add_argument("--allow-state-changing-http", action="store_true")
    hunt_start.add_argument("--network-discovery", action="store_true")
    hunt_start.add_argument("--allow-oob-interactions", action="store_true")
    hunt_start.add_argument("--authorized", action="store_true")
    hunt_start.add_argument("--approval-receipt-id")
    hunt_start.add_argument("--scope-receipt-id")
    hunt_start.add_argument("--budget", action="append", default=[], metavar="NAME=VALUE")
    hunt_start.add_argument("--credential-ref", action="append", default=[], metavar="SLOT=ID")
    hunt_start.add_argument("--capability", action="append", default=[])
    hunt_start.add_argument("--collection-id", action="append", default=[])

    hunt_call = hunt_commands.add_parser("call", help="Call one server-returned capability")
    hunt_call.add_argument("hunt_id")
    hunt_call.add_argument("capability_name")
    hunt_call.add_argument("--input", metavar="FILE", help="JSON object; use - for stdin")
    hunt_call.add_argument("--idempotency-key")

    credentials = products.add_parser(
        "credentials", help="Create, rotate, or admission-test an encrypted profile",
    )
    credential_commands = credentials.add_subparsers(
        dest="credentials_command", required=True,
    )
    credential_create = credential_commands.add_parser(
        "create", help="Create from server-contract JSON read from a file or stdin",
    )
    credential_create.add_argument("--request", required=True, metavar="FILE")
    credential_create.add_argument("--idempotency-key")
    credential_rotate = credential_commands.add_parser(
        "rotate", help="Rotate from server-contract JSON read from a file or stdin",
    )
    credential_rotate.add_argument("profile_id")
    credential_rotate.add_argument("--request", required=True, metavar="FILE")
    credential_rotate.add_argument("--idempotency-key")
    credential_test = credential_commands.add_parser(
        "test", help="Run a content-free storage and execution-admission check",
    )
    credential_test.add_argument("profile_id")
    credential_test.add_argument("--capability")

    collections = products.add_parser(
        "collections", help="Upload, bind, or select an encrypted request collection",
    )
    collection_commands = collections.add_subparsers(
        dest="collections_command", required=True,
    )
    collection_upload = collection_commands.add_parser(
        "upload", help="Import Postman, HAR, OpenAPI, or Swagger input",
    )
    collection_upload.add_argument("document", nargs="?")
    collection_upload.add_argument("--request", metavar="FILE")
    collection_upload.add_argument("--target-id")
    collection_upload.add_argument("--name")
    collection_upload.add_argument("--format", default="auto")
    collection_upload.add_argument("--environment")
    collection_upload.add_argument("--environment-name")
    collection_upload.add_argument("--base-url")
    collection_upload.add_argument("--import-limit", type=int, default=5_000)
    collection_upload.add_argument("--idempotency-key")
    collection_bind = collection_commands.add_parser(
        "bind", help="Bind a collection to one exact target and origin set",
    )
    collection_bind.add_argument("collection_id")
    collection_bind.add_argument("--request", metavar="FILE")
    collection_bind.add_argument("--target-kind")
    collection_bind.add_argument("--target-id")
    collection_bind.add_argument("--allowed-origin", action="append", default=[])
    collection_bind.add_argument("--environment-id")
    collection_bind.add_argument("--idempotency-key")
    collection_select = collection_commands.add_parser(
        "select", help="Preview one redacted bounded request selection",
    )
    collection_select.add_argument("collection_id")
    collection_select.add_argument("--request", metavar="FILE")
    collection_select.add_argument("--request-id", action="append", default=[])
    collection_select.add_argument("--folder", action="append", default=[])
    collection_select.add_argument("--method", action="append", default=[])
    collection_select.add_argument("--path-regex")
    collection_select.add_argument("--tag", action="append", default=[])
    collection_select.add_argument("--include-mutating", action="store_true")
    collection_select.add_argument("--limit", type=int, default=500)
    collection_select.add_argument("--idempotency-key")

    evidence = products.add_parser(
        "evidence", help="Export content-free evidence manifests or bundles",
    )
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_export = evidence_commands.add_parser(
        "export", help="Export a filtered manifest, JSON bundle, or metadata zip",
    )
    evidence_export.add_argument("--scan-id")
    evidence_export.add_argument("--finding-id")
    evidence_export.add_argument("--retention-class")
    evidence_export.add_argument("--limit", type=int, default=200)
    evidence_export.add_argument("--format", choices=("manifest", "json", "zip"), default="manifest")
    evidence_export.add_argument("--record-event", action="store_true")
    evidence_export.add_argument("--output")
    evidence_export.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        client = ApiClient(args.api_url)
        if args.product == "hunt":
            result = _run_hunt(args, client)
        elif args.product == "credentials":
            result = _run_credentials(args, client)
        elif args.product == "collections":
            result = _run_collections(args, client)
        elif args.product == "evidence":
            result = _run_evidence(args, client)
        else:
            raise CliError("unknown command")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except CliError as exc:
        print(json.dumps(exc.public_dict(), sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
