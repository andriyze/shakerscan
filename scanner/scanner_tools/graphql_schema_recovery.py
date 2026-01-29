"""
GraphQL Schema Recovery Module (Clairvoyance Methodology)

Recovers GraphQL schemas when introspection is disabled by using:
1. Field suggestion errors to enumerate types and fields
2. Type hint errors to discover argument types
3. Brute-force common field/type names
4. Error message analysis for schema structure

Based on the Clairvoyance methodology:
https://github.com/nikitastupin/clairvoyance

IMPORTANT: This module is for DEFENSIVE security testing - helping
organizations discover what an attacker could learn about their
GraphQL API through error messages.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GraphQLField:
    """Represents a discovered GraphQL field"""
    name: str
    parent_type: str
    return_type: str | None = None
    arguments: list[dict] = field(default_factory=list)
    is_deprecated: bool = False
    confidence: str = "suggested"  # suggested, confirmed, brute_force


@dataclass
class GraphQLType:
    """Represents a discovered GraphQL type"""
    name: str
    kind: str = "OBJECT"  # OBJECT, INPUT_OBJECT, ENUM, SCALAR, INTERFACE, UNION
    fields: list[GraphQLField] = field(default_factory=list)
    enum_values: list[str] = field(default_factory=list)


@dataclass
class RecoveredSchema:
    """Represents a partially recovered GraphQL schema"""
    types: dict[str, GraphQLType] = field(default_factory=dict)
    query_type: str = "Query"
    mutation_type: str | None = None
    subscription_type: str | None = None


# Common GraphQL type names for brute-forcing
COMMON_TYPE_NAMES = [
    "Query", "Mutation", "Subscription",
    "User", "Users", "Account", "Profile", "Person",
    "Post", "Posts", "Article", "Articles", "Content",
    "Comment", "Comments", "Reply", "Message", "Messages",
    "Product", "Products", "Item", "Items", "Order", "Orders",
    "Category", "Categories", "Tag", "Tags",
    "File", "Image", "Document", "Attachment",
    "Role", "Permission", "Group", "Team",
    "Session", "Token", "Auth", "Authentication",
    "Setting", "Config", "Configuration", "Preference",
    "Notification", "Alert", "Event", "Log",
    "Admin", "Dashboard", "Analytics", "Metric",
    "Connection", "Edge", "Node", "PageInfo",
    "Error", "Result", "Response", "Payload",
]

# Common field names for brute-forcing (organized by category)
COMMON_FIELD_NAMES = {
    "identity": [
        "id", "uuid", "uid", "_id", "objectId", "identifier",
    ],
    "user_fields": [
        "user", "users", "me", "viewer", "currentUser", "self",
        "profile", "account", "member", "owner", "author", "creator",
        "admin", "admins", "administrator", "moderator",
    ],
    "auth_fields": [
        "login", "logout", "authenticate", "register", "signup",
        "token", "accessToken", "refreshToken", "apiKey",
        "session", "sessions", "password", "credentials",
        "permissions", "roles", "scopes",
    ],
    "content_fields": [
        "posts", "post", "articles", "article", "content",
        "comments", "comment", "messages", "message",
        "notifications", "notification", "feeds", "feed",
    ],
    "crud_fields": [
        "get", "list", "all", "find", "search", "query",
        "create", "add", "new", "insert",
        "update", "edit", "modify", "patch",
        "delete", "remove", "destroy",
    ],
    "common_attributes": [
        "name", "title", "description", "body", "text", "content",
        "email", "phone", "address", "url", "link", "website",
        "createdAt", "updatedAt", "deletedAt", "timestamp",
        "status", "state", "type", "kind", "category",
        "count", "total", "size", "length",
        "enabled", "active", "visible", "public", "private",
        "metadata", "data", "info", "details", "config",
    ],
    "relations": [
        "parent", "children", "child", "items", "edges", "nodes",
        "connection", "connections", "relations", "related",
    ],
    "pagination": [
        "first", "last", "before", "after", "skip", "take",
        "limit", "offset", "page", "pageSize", "cursor",
        "hasNextPage", "hasPreviousPage", "totalCount",
    ],
    "filtering": [
        "where", "filter", "filters", "orderBy", "sortBy",
        "query", "search", "input", "args",
    ],
    "sensitive": [
        "secret", "secrets", "key", "keys", "apiKey", "apiKeys",
        "token", "tokens", "credential", "credentials",
        "internal", "debug", "test", "admin", "system",
        "flag", "flags", "feature", "features",
    ],
}

# Flatten field names for quick access
ALL_FIELD_NAMES = []
for category_fields in COMMON_FIELD_NAMES.values():
    ALL_FIELD_NAMES.extend(category_fields)
ALL_FIELD_NAMES = list(set(ALL_FIELD_NAMES))


def extract_suggestions_from_error(error_message: str) -> list[str]:
    """
    Extract field/type suggestions from GraphQL error messages.

    Args:
        error_message: GraphQL error message

    Returns:
        List of suggested names
    """
    suggestions = []

    # Common suggestion patterns in GraphQL error messages
    patterns = [
        # "Did you mean X?"
        r'[Dd]id you mean ["\']?(\w+)["\']?\??',
        # "Perhaps you meant X"
        r'[Pp]erhaps you meant ["\']?(\w+)["\']?',
        # "Unknown field X. Did you mean Y?"
        r'[Uu]nknown field ["\']?\w+["\']?\. [Dd]id you mean ["\']?(\w+)["\']?\??',
        # "Cannot query field X. Did you mean Y or Z?"
        r'[Cc]annot query field ["\']?\w+["\']?\. [Dd]id you mean ["\']?(\w+)["\']?',
        r'[Cc]annot query field ["\']?\w+["\']?\. [Dd]id you mean \w+ or ["\']?(\w+)["\']?\??',
        # "Suggested: X, Y, Z"
        r'[Ss]uggested:\s*([^\.]+)',
        # Apollo/graphql-js style multiple suggestions
        r'[Dd]id you mean (?:one of )?["\']?(\w+)["\']?(?:,\s*["\']?(\w+)["\']?)*(?:\s+or\s+["\']?(\w+)["\']?)?',
        # Field not found with suggestions
        r'[Ff]ield ["\']?\w+["\']? (?:not found|doesn\'t exist)[\.\s]+[Ss]imilar: ["\']?(\w+)["\']?',
        # Type suggestions
        r'[Tt]ype ["\']?\w+["\']? not found[\.\s]+[Dd]id you mean ["\']?(\w+)["\']?\??',
        # Enum value suggestions
        r'[Ii]nvalid value for enum[\.\s]+[Dd]id you mean ["\']?(\w+)["\']?\??',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, error_message)
        for match in matches:
            if isinstance(match, tuple):
                suggestions.extend([m for m in match if m])
            elif isinstance(match, str):
                # Handle comma-separated suggestions
                for suggestion in match.split(","):
                    suggestion = suggestion.strip().strip("'\"")
                    if suggestion and suggestion.isidentifier():
                        suggestions.append(suggestion)

    return list(set(suggestions))


def extract_type_info_from_error(error_message: str) -> dict[str, Any]:
    """
    Extract type information from GraphQL error messages.

    Args:
        error_message: GraphQL error message

    Returns:
        Dict with type information
    """
    info = {}

    # Extract expected type
    type_patterns = [
        r'expected (?:type )?["\']?(\w+)["\']?',
        r'must be (?:of type )?["\']?(\w+)["\']?',
        r'got ["\']?\w+["\']?, expected ["\']?(\w+)["\']?',
        r'argument ["\']?\w+["\']? of type ["\']?(\w+)["\']?',
        r'[Tt]ype mismatch[\.\s]+[Ee]xpected ["\']?(\w+)["\']?',
    ]

    for pattern in type_patterns:
        match = re.search(pattern, error_message)
        if match:
            info["expected_type"] = match.group(1)
            break

    # Check if it's a non-null type
    if "non-null" in error_message.lower() or "required" in error_message.lower():
        info["is_required"] = True

    # Check if it's a list type
    if "list" in error_message.lower() or "array" in error_message.lower():
        info["is_list"] = True

    return info


async def probe_field(
    client: httpx.AsyncClient,
    graphql_url: str,
    type_name: str,
    field_name: str,
    headers: dict | None = None,
) -> tuple[bool, list[str], dict]:
    """
    Probe for a field existence and get suggestions.

    Args:
        client: HTTP client
        graphql_url: GraphQL endpoint URL
        type_name: Type to query (e.g., "Query")
        field_name: Field name to probe
        headers: Optional headers

    Returns:
        Tuple of (field_exists, suggestions, type_info)
    """
    # Build probe query
    if type_name in ("Query", "Mutation", "Subscription"):
        query = f"{{ {field_name} }}"
    else:
        # For other types, we need a path to them
        query = f"{{ __typename {field_name} }}"

    request_headers = headers or {}
    request_headers["Content-Type"] = "application/json"

    try:
        resp = await client.post(
            graphql_url,
            json={"query": query},
            headers=request_headers,
            timeout=10.0,
        )

        if resp.status_code != 200:
            return False, [], {}

        data = resp.json()
        errors = data.get("errors", [])
        result_data = data.get("data")

        # If we got data, the field exists
        if result_data and field_name in result_data:
            return True, [], {}

        # Check errors for suggestions
        suggestions = []
        type_info = {}

        for error in errors:
            message = error.get("message", "")

            # Check if field doesn't exist (expected for probing)
            if any(x in message.lower() for x in ["cannot query", "unknown field", "not found", "doesn't exist"]):
                suggestions.extend(extract_suggestions_from_error(message))
                type_info.update(extract_type_info_from_error(message))

            # Field exists but has errors (e.g., missing required args)
            elif any(x in message.lower() for x in ["argument", "required", "missing", "type mismatch"]):
                return True, [], extract_type_info_from_error(message)

        # If data is null but no "not found" error, field might exist
        if result_data is not None and result_data.get(field_name) is None and not errors:
            return True, [], {}

        return False, list(set(suggestions)), type_info

    except Exception as e:
        logger.debug(f"Probe failed for {field_name}: {e}")
        return False, [], {}


async def probe_type(
    client: httpx.AsyncClient,
    graphql_url: str,
    type_name: str,
    headers: dict | None = None,
) -> tuple[bool, list[str]]:
    """
    Probe for a type existence using __typename.

    Args:
        client: HTTP client
        graphql_url: GraphQL endpoint URL
        type_name: Type name to probe
        headers: Optional headers

    Returns:
        Tuple of (type_exists, suggestions)
    """
    # Use fragment spread to check type
    query = f"""
    {{
        __typename
        ... on {type_name} {{
            __typename
        }}
    }}
    """

    request_headers = headers or {}
    request_headers["Content-Type"] = "application/json"

    try:
        resp = await client.post(
            graphql_url,
            json={"query": query},
            headers=request_headers,
            timeout=10.0,
        )

        if resp.status_code != 200:
            return False, []

        data = resp.json()
        errors = data.get("errors", [])

        suggestions = []
        for error in errors:
            message = error.get("message", "")
            if any(x in message.lower() for x in ["unknown type", "type not found", "undefined type"]):
                suggestions.extend(extract_suggestions_from_error(message))
            elif "abstract type" not in message.lower():
                # Type exists if no "not found" error
                return True, []

        return False, list(set(suggestions))

    except Exception as e:
        logger.debug(f"Type probe failed for {type_name}: {e}")
        return False, []


async def recover_schema(
    graphql_url: str,
    auth_header: str | None = None,
    max_fields_per_type: int = 50,
    probe_timeout: float = 5.0,
    include_brute_force: bool = True,
) -> RecoveredSchema:
    """
    Recover GraphQL schema using error-based enumeration.

    Args:
        graphql_url: GraphQL endpoint URL
        auth_header: Optional authorization header
        max_fields_per_type: Maximum fields to discover per type
        probe_timeout: Timeout for each probe
        include_brute_force: Whether to brute-force common field names

    Returns:
        RecoveredSchema with discovered types and fields
    """
    schema = RecoveredSchema()
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    async with httpx.AsyncClient(verify=False) as client:
        # Phase 1: Probe root types (Query, Mutation, Subscription)
        logger.info("Phase 1: Probing root types")
        for root_type in ["Query", "Mutation", "Subscription"]:
            exists, suggestions = await probe_type(client, graphql_url, root_type, headers)
            if exists or root_type == "Query":  # Query always exists
                schema.types[root_type] = GraphQLType(name=root_type, kind="OBJECT")

                if root_type == "Mutation":
                    schema.mutation_type = root_type
                elif root_type == "Subscription":
                    schema.subscription_type = root_type

        # Phase 2: Discover fields on Query type using suggestions
        logger.info("Phase 2: Discovering Query fields via suggestions")
        discovered_fields = set()
        pending_probes = list(ALL_FIELD_NAMES[:20])  # Start with common fields

        # Initial probes to get suggestions
        for field_name in pending_probes[:10]:
            exists, suggestions, type_info = await probe_field(
                client, graphql_url, "Query", field_name, headers
            )

            if exists:
                discovered_fields.add(field_name)
                gql_field = GraphQLField(
                    name=field_name,
                    parent_type="Query",
                    confidence="confirmed",
                )
                schema.types["Query"].fields.append(gql_field)
                logger.info(f"Confirmed field: Query.{field_name}")

            for suggestion in suggestions:
                if suggestion not in discovered_fields and suggestion not in pending_probes:
                    pending_probes.append(suggestion)

            await asyncio.sleep(0.1)  # Rate limiting

        # Follow up on suggestions
        suggestion_probes = [p for p in pending_probes if p not in ALL_FIELD_NAMES[:10]]
        for field_name in suggestion_probes[:max_fields_per_type]:
            if field_name in discovered_fields:
                continue

            exists, new_suggestions, type_info = await probe_field(
                client, graphql_url, "Query", field_name, headers
            )

            if exists:
                discovered_fields.add(field_name)
                gql_field = GraphQLField(
                    name=field_name,
                    parent_type="Query",
                    confidence="suggested",
                )
                schema.types["Query"].fields.append(gql_field)
                logger.info(f"Discovered field via suggestion: Query.{field_name}")

            for suggestion in new_suggestions:
                if suggestion not in discovered_fields and suggestion not in pending_probes:
                    pending_probes.append(suggestion)

            await asyncio.sleep(0.1)

        # Phase 3: Brute-force remaining common fields
        if include_brute_force:
            logger.info("Phase 3: Brute-forcing common field names")
            remaining_fields = [f for f in ALL_FIELD_NAMES if f not in discovered_fields]

            for field_name in remaining_fields[:max_fields_per_type - len(discovered_fields)]:
                exists, _, type_info = await probe_field(
                    client, graphql_url, "Query", field_name, headers
                )

                if exists:
                    discovered_fields.add(field_name)
                    gql_field = GraphQLField(
                        name=field_name,
                        parent_type="Query",
                        confidence="brute_force",
                    )
                    schema.types["Query"].fields.append(gql_field)
                    logger.info(f"Found field via brute-force: Query.{field_name}")

                await asyncio.sleep(0.05)  # Faster for brute force

        # Phase 4: Probe Mutation fields if exists
        if schema.mutation_type:
            logger.info("Phase 4: Discovering Mutation fields")
            mutation_discovered = set()

            # Common mutation prefixes
            mutation_prefixes = [
                "create", "update", "delete", "add", "remove", "set",
                "login", "logout", "register", "signup", "signin",
                "send", "submit", "upload", "save", "reset",
            ]

            mutation_targets = [
                "User", "Post", "Comment", "Item", "Order",
                "Message", "Notification", "Setting", "Password",
            ]

            mutation_fields = mutation_prefixes.copy()
            for prefix in mutation_prefixes:
                for target in mutation_targets:
                    mutation_fields.append(f"{prefix}{target}")

            for field_name in mutation_fields[:30]:
                exists, suggestions, _ = await probe_field(
                    client, graphql_url, "Mutation", field_name, headers
                )

                if exists:
                    mutation_discovered.add(field_name)
                    gql_field = GraphQLField(
                        name=field_name,
                        parent_type="Mutation",
                        confidence="brute_force",
                    )
                    schema.types["Mutation"].fields.append(gql_field)
                    logger.info(f"Found mutation: {field_name}")

                for suggestion in suggestions:
                    if suggestion not in mutation_discovered:
                        # Probe suggestion
                        exists, _, _ = await probe_field(
                            client, graphql_url, "Mutation", suggestion, headers
                        )
                        if exists:
                            mutation_discovered.add(suggestion)
                            gql_field = GraphQLField(
                                name=suggestion,
                                parent_type="Mutation",
                                confidence="suggested",
                            )
                            schema.types["Mutation"].fields.append(gql_field)

                await asyncio.sleep(0.05)

    return schema


def schema_to_dict(schema: RecoveredSchema) -> dict[str, Any]:
    """Convert RecoveredSchema to a dictionary for JSON serialization."""
    return {
        "query_type": schema.query_type,
        "mutation_type": schema.mutation_type,
        "subscription_type": schema.subscription_type,
        "types": {
            name: {
                "name": t.name,
                "kind": t.kind,
                "fields": [
                    {
                        "name": f.name,
                        "return_type": f.return_type,
                        "arguments": f.arguments,
                        "confidence": f.confidence,
                    }
                    for f in t.fields
                ],
                "enum_values": t.enum_values,
            }
            for name, t in schema.types.items()
        },
    }


def schema_to_sdl(schema: RecoveredSchema) -> str:
    """Convert RecoveredSchema to GraphQL SDL format."""
    lines = []
    lines.append("# Recovered GraphQL Schema (partial)")
    lines.append("# Fields marked with comments indicate confidence level\n")

    for type_name, gql_type in schema.types.items():
        if gql_type.kind == "OBJECT":
            lines.append(f"type {type_name} {{")
            for field in gql_type.fields:
                return_type = field.return_type or "Unknown"
                confidence = f"  # {field.confidence}"
                lines.append(f"  {field.name}: {return_type}{confidence}")
            lines.append("}\n")

        elif gql_type.kind == "ENUM" and gql_type.enum_values:
            lines.append(f"enum {type_name} {{")
            for value in gql_type.enum_values:
                lines.append(f"  {value}")
            lines.append("}\n")

    return "\n".join(lines)


async def run_schema_recovery(
    url: str,
    graphql_url: str | None = None,
    auth_header: str | None = None,
    thorough: bool = False,
) -> dict[str, Any]:
    """
    Main entry point for GraphQL schema recovery.

    Args:
        url: Base URL
        graphql_url: Optional GraphQL endpoint (auto-discovered if not provided)
        auth_header: Optional authorization header
        thorough: Whether to perform thorough brute-forcing

    Returns:
        Dict with recovered schema, findings, and summary
    """
    results = {
        "success": False,
        "graphql_url": graphql_url,
        "schema": None,
        "schema_sdl": None,
        "findings": [],
        "summary": {
            "types_discovered": 0,
            "fields_discovered": 0,
            "confirmed_fields": 0,
            "suggested_fields": 0,
            "brute_forced_fields": 0,
        },
    }

    # Auto-discover GraphQL endpoint if not provided
    if not graphql_url:
        common_endpoints = ["/graphql", "/graphql/v2", "/api/graphql", "/query", "/gql"]
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header

        async with httpx.AsyncClient(verify=False, headers=headers) as client:
            for endpoint in common_endpoints:
                test_url = url.rstrip("/") + endpoint
                try:
                    resp = await client.post(
                        test_url,
                        json={"query": "{ __typename }"},
                        headers={"Content-Type": "application/json"},
                        timeout=5.0,
                    )
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if "data" in data or "errors" in data:
                                graphql_url = test_url
                                break
                        except json.JSONDecodeError:
                            pass
                except httpx.RequestError:
                    pass

    if not graphql_url:
        results["error"] = "GraphQL endpoint not found"
        return results

    results["graphql_url"] = graphql_url

    # Recover schema
    try:
        schema = await recover_schema(
            graphql_url=graphql_url,
            auth_header=auth_header,
            max_fields_per_type=100 if thorough else 50,
            include_brute_force=True,
        )

        results["success"] = True
        results["schema"] = schema_to_dict(schema)
        results["schema_sdl"] = schema_to_sdl(schema)

        # Calculate summary
        total_fields = 0
        confirmed = 0
        suggested = 0
        brute_forced = 0

        for gql_type in schema.types.values():
            total_fields += len(gql_type.fields)
            for field in gql_type.fields:
                if field.confidence == "confirmed":
                    confirmed += 1
                elif field.confidence == "suggested":
                    suggested += 1
                elif field.confidence == "brute_force":
                    brute_forced += 1

        results["summary"] = {
            "types_discovered": len(schema.types),
            "fields_discovered": total_fields,
            "confirmed_fields": confirmed,
            "suggested_fields": suggested,
            "brute_forced_fields": brute_forced,
        }

        # Add findings
        if total_fields > 0:
            results["findings"].append({
                "type": "schema_recovered",
                "severity": "medium",
                "description": f"Recovered {total_fields} fields across {len(schema.types)} types via error messages",
                "evidence": {
                    "endpoint": graphql_url,
                    "types": list(schema.types.keys()),
                    "sample_fields": [
                        f"{t.name}.{f.name}"
                        for t in schema.types.values()
                        for f in t.fields[:3]
                    ][:10],
                },
                "remediation": (
                    "Disable GraphQL field suggestions in production. "
                    "Most GraphQL implementations have options to suppress "
                    "detailed error messages."
                ),
            })

        # Check for sensitive fields
        sensitive_patterns = ["admin", "secret", "token", "password", "key", "internal", "debug"]
        sensitive_found = []
        for gql_type in schema.types.values():
            for field in gql_type.fields:
                for pattern in sensitive_patterns:
                    if pattern in field.name.lower():
                        sensitive_found.append(f"{gql_type.name}.{field.name}")
                        break

        if sensitive_found:
            results["findings"].append({
                "type": "sensitive_fields_discovered",
                "severity": "high",
                "description": f"Discovered {len(sensitive_found)} potentially sensitive field names",
                "evidence": {
                    "sensitive_fields": sensitive_found[:20],
                },
                "remediation": (
                    "Review and restrict access to sensitive fields. "
                    "Consider implementing field-level authorization."
                ),
            })

    except Exception as e:
        results["error"] = str(e)
        logger.error(f"Schema recovery failed: {e}")

    return results
