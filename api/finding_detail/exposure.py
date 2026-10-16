"""Sensitive-exposure findings: what was served, which secrets it held (masked) and how to close it."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .common import command, fact, facts, integer, join_limited, origin_of, q, record, strings, text, url_parts

_SECRET_REF = re.compile(r"^secret://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# class -> (label, what it is, why it matters, fix steps)
_CLASSES: Mapping[str, tuple[str, str, str, list[str]]] = {
    "environment_secret_file": (
        "Environment file with secrets", "an environment (.env-style) file",
        "Anyone can download it without signing in; every value it holds must be treated as known to attackers.",
        ["Remove the file from the web root (it belongs next to the application, not under the document root).",
         "Deny dotfiles at the web server: nginx location ~ /\\.(?!well-known) { deny all; } · Apache <FilesMatch \"^\\.\"> Require all denied </FilesMatch>",
         "Rotate every credential named below — removing the file does not un-leak them."],
    ),
    "configuration_secret_file": (
        "Configuration file with secrets", "an application configuration file",
        "The file holds credentials or keys the application uses; anyone who fetched it can use them.",
        ["Stop serving the file: move it out of the web root or deny its extension (web.config, *.json, *.yml, *.php.bak) at the server.",
         "Rotate every credential named below.", "Load secrets from the environment or a secret manager instead of files under the web root."],
    ),
    "cloud_credential_material": (
        "Cloud credentials exposed", "cloud provider credentials",
        "Cloud keys give direct access to the account's resources and are actively harvested from public pages.",
        ["Deactivate the exposed keys in the provider console now, then issue new ones.",
         "Review the provider's audit log (e.g. CloudTrail) for use of the exposed key since it was first served.",
         "Remove the key from the served content and from source history."],
    ),
    "private_key_material": (
        "Private key exposed", "a private key",
        "Whoever holds the key can impersonate the server or user it belongs to and decrypt what it protects.",
        ["Stop serving the file.", "Revoke the key: reissue certificates or replace the SSH/deploy key that used it.",
         "Check where the key was trusted (authorized_keys, CA, deploy settings) and remove it there."],
    ),
    "html_comment_secret": (
        "Secret in an HTML comment", "an HTML comment containing a credential",
        "Every visitor's browser receives the page source, including this comment.",
        ["Remove the comment from the template and rotate the credential it held.",
         "Strip comments in the production build (most bundlers and template engines can)."],
    ),
    "credential_record_disclosure": (
        "Credential records disclosed", "user records with credentials",
        "Anonymous visitors can read account credentials of other users.",
        ["Require authentication and authorization on this endpoint.", "Never return password fields; store only salted password hashes.",
         "Force a password reset for the affected accounts."],
    ),
    "api_specification_secret": (
        "Secret in an API specification", "an API description (OpenAPI/Swagger) with a credential in it",
        "API documents are fetched by tools and indexed; the key in the example or default value is usable.",
        ["Remove the live key from the specification (use a placeholder) and rotate it.",
         "Serve the specification only to authenticated users if it describes internal APIs."],
    ),
    "actuator_secret_disclosure": (
        "Spring Boot Actuator discloses secrets", "Spring Boot Actuator endpoints (env/configprops)",
        "Actuator lists configuration properties, including credentials, to anyone who can reach it.",
        ["Expose only health over HTTP: management.endpoints.web.exposure.include=health",
         "Move management endpoints to a separate internal port (management.server.port) or require authentication.",
         "Rotate the credentials named below."],
    ),
    "actuator_heapdump_exposed": (
        "Heap dump downloadable", "a JVM heap dump endpoint",
        "A heap dump contains everything in the application's memory: sessions, passwords, keys and user data.",
        ["Disable the heapdump endpoint (management.endpoint.heapdump.enabled=false) or keep it off the public port.",
         "Rotate secrets the application held in memory if the dump may have been downloaded."],
    ),
    "version_control_exposure": (
        "Git repository exposed", "version-control metadata (.git)",
        "Tools such as git-dumper rebuild the whole repository from it — source, history and any secret ever committed.",
        ["Remove the .git directory from the deployed web root (deploy with git archive or a build artifact).",
         "Deny /.git at the web server.", "Review the repository history for committed secrets and rotate them."],
    ),
    "backup_or_source_artifact": (
        "Backup or source archive downloadable", "a backup, dump or source archive",
        "Archives and dumps usually contain source code, database contents and credentials.",
        ["Delete backups from the web root and store them outside it.", "Rotate credentials contained in the archive.",
         "Deny backup extensions (.bak, .old, .sql, .zip, .tar.gz) at the web server."],
    ),
    "confidential_file": (
        "Confidential file reachable", "a file that should not be public",
        "The file's content is readable by anyone.", ["Remove the file from the web root or require authentication for it."],
    ),
    "directory_listing": (
        "Directory listing enabled", "an automatically generated directory index",
        "Lists every file in the directory, including ones nobody linked to.",
        ["Disable automatic indexes: nginx autoindex off; · Apache Options -Indexes · IIS directoryBrowse enabled=\"false\"",
         "Review the listed files and remove any that should not be public."],
    ),
    "directory_metadata_file": (
        "Directory metadata file", "a directory metadata file (.DS_Store or similar)",
        "It reveals the names of files and folders, which helps find unlinked content.",
        ["Delete the file and exclude it from deployments.", "Deny dotfiles at the web server."],
    ),
    "metrics_endpoint": (
        "Metrics endpoint public", "an internal metrics or status endpoint",
        "It reveals internal names, versions, routes and load figures that help plan an attack.",
        ["Serve metrics on an internal interface or port only, or require authentication.",
         "Apache: restrict /server-status to Require local / internal addresses."],
    ),
    "phpinfo_disclosure": (
        "phpinfo() page public", "a phpinfo() page",
        "It shows PHP and server versions, loaded modules, paths and environment variables.",
        ["Delete the file that calls phpinfo().", "Check the page's environment section for secrets and rotate any it showed."],
    ),
    "debug_interface_exposure": (
        "Debug interface public", "a debugging interface",
        "Debug consoles and profilers expose internals; some (Werkzeug console) allow running code on the server.",
        ["Turn debug mode off in production (FLASK_DEBUG=0 / DEBUG=False; do not register net/http/pprof on the public mux).",
         "Restrict any remaining diagnostic endpoint to internal addresses."],
    ),
    "verbose_error_disclosure": (
        "Verbose error messages", "a detailed error page (stack trace or framework error)",
        "Stack traces reveal frameworks, versions, file paths and code structure, and sometimes query fragments or values.",
        ["Turn off debug/detailed errors in production and return a generic error page.",
         "Log the detail on the server instead (with a correlation id shown to the user)."],
    ),
    "graphql_introspection_enabled": (
        "GraphQL introspection enabled", "the full GraphQL schema via introspection",
        "Anyone can list every type, query and mutation, including internal or admin operations.",
        ["Disable introspection in production (Apollo Server: introspection: false; graphql-java: NO_INTROSPECTION_FIELD_VISIBILITY)."],
    ),
    "graphql_ide_exposure": (
        "GraphQL IDE served", "an in-browser GraphQL IDE (GraphiQL / Playground)",
        "It gives anyone a convenient console to explore and call the API.",
        ["Disable the IDE in production builds or serve it only to authenticated developers."],
    ),
}


def secret_refs(evidence: Mapping[str, Any]) -> list[str]:
    refs = [ref for ref in strings(evidence.get("discovered_refs"), 20, 60) if _SECRET_REF.match(ref)]
    for entry in evidence.get("exposure_fingerprints") or ():
        ref = text(record(entry).get("stored_as"), 60)
        if _SECRET_REF.match(ref) and ref not in refs:
            refs.append(ref)
    return refs[:20]


def build(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    exposure_class = text(evidence.get("exposure_class"), 80)
    label, what, why, fix = _CLASSES.get(exposure_class, (
        exposure_class.replace("_", " ").capitalize() or "Sensitive exposure", "sensitive content", "", [],
    ))
    url = text(evidence.get("request_url") or finding.get("url"), 600)
    _scheme, _host, _port, path = url_parts(url)
    status = evidence.get("response_status")
    fingerprints = [record(entry) for entry in evidence.get("exposure_fingerprints") or () if isinstance(entry, Mapping)][:50]
    fields = [text(entry.get("field"), 120) or text(entry.get("category"), 60) for entry in fingerprints]
    fields = [name for name in fields if name]
    secrets = [
        {
            "field": text(entry.get("field"), 120),
            "category": text(entry.get("category"), 60).replace("_", " "),
            "length": integer(entry.get("value_length")),
            **({"ref": text(entry.get("stored_as"), 60)} if _SECRET_REF.match(text(entry.get("stored_as"), 60)) else {}),
        }
        for entry in fingerprints
    ]
    summary = f"{url or path} served {what} to an anonymous request" + (f" (HTTP {status})" if status else "") + "."
    if secrets:
        summary += f" It contained {len(secrets)} secret value{'s' if len(secrets) != 1 else ''}: {join_limited(fields, 6)}."
    context = [why] if why else []
    if secrets:
        context.append("The values are not shown here: the scanner stores only the field name, kind and length, and keeps any reusable value in the target's discovered secrets.")
    via = text(evidence.get("discovered_via"), 80)
    if via:
        context.append(f"The scanner reached this path via {via.replace('_', ' ')}.")
    excerpt = text(evidence.get("redacted_excerpt"), 1200)
    curl = f"curl -sS -o /dev/null -w '%{{http_code}} %{{content_type}} %{{size_download}} bytes\\n' {q(url)}"
    return {
        "class": f"exposure.{exposure_class}" if exposure_class else "exposure",
        "class_label": label,
        "summary": summary,
        "where": facts(fact("URL", url, mono=True), fact("Origin", origin_of(url), mono=True)),
        "observed": facts(
            fact("Response status", status, mono=True), fact("Content type", evidence.get("content_type"), mono=True),
            fact("Matched signature", evidence.get("matched_signature"), mono=True),
        ),
        "secrets": secrets,
        "excerpt": {"label": "Response excerpt (masked by the scanner)", "text": excerpt} if excerpt else None,
        "expected": ["404 or 403: this content should not be served to anonymous users."],
        "context": context,
        "reproduce": command(curl, expect=f"{status or 200} with a non-empty body", note="Prints only status, type and size, never the content."),
        "verify": command(curl, expect="404 or 403"),
        "fix": list(fix) + ([f"Credentials to rotate: {join_limited(fields, 12)}."] if secrets and not any("named below" in step for step in fix) else []),
        "secret_refs": secret_refs(evidence),
    }


__all__ = ["build", "secret_refs"]
