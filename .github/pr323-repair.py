"""One-shot, guarded source repair for the reviewed PR head; not a runtime dependency."""
from pathlib import Path
import ast
import hashlib

ROOT = Path.cwd()
EXPECTED = {
    'api/api.py': 'd90ddcb3cb0d884628d88d1a002d29782e350a93',
    'scanner.sh': 'f5323e3c59a9311993c86d98b9f65b6381e930a1',
    'api/capabilities/authentication_proof.py': '309c0ac7604f89ba0be03a75f9d044d035df204a',
    'api/runtime/ai_template_secrets.py': 'c13d8700fe0cac7fbc7d01f0c92d61d3536e2732',
}

def verify():
    for name, expected in EXPECTED.items():
        data = (ROOT / name).read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if actual != expected:
            raise RuntimeError(f'Refusing to overwrite changed source: {name}')


def replace(name, old, new):
    p = ROOT / name
    text = p.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f'Expected exactly one edit anchor in {name}: {old[:70]!r}')
    p.write_text(text.replace(old, new))


def function(name, symbol, new):
    p = ROOT / name
    text = p.read_text()
    matches = [n for n in ast.parse(text).body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == symbol]
    if len(matches) != 1:
        raise RuntimeError(f'Expected one function {name}:{symbol}')
    node = matches[0]
    lines = text.splitlines(keepends=True)
    p.write_text(''.join(lines[:node.lineno - 1]) + new.rstrip() + '\n' + ''.join(lines[node.end_lineno:]))


def append(name, text):
    p = ROOT / name
    p.write_text(p.read_text().rstrip() + '\n\n\n' + text.strip() + '\n')


AUTH = '''def successful_token_signals(result: Any) -> tuple[str, ...]:
    """Return content-free token assertions, vetoed by their own login state.

    Candidate ancestors are login scope even when an API uses an unfamiliar
    wrapper name. Unrelated user/subscription metadata is not a login verdict.
    Cookies and ambiguous generic tokens remain candidates, not bypass proof.
    """
    if not isinstance(result.status_code, int) or not 200 <= result.status_code < 300:
        return ()
    signals = {
        str(name).lower() for name, value in result.response_headers.items()
        if str(name).lower() in {"authorization", "x-auth-token"}
        and isinstance(value, str) and value.strip()
    }
    content_type = next((str(v).lower() for k, v in result.response_headers.items()
                         if str(k).lower() == "content-type"), "")
    if "json" not in content_type or not result.response_body:
        return tuple(sorted(signals))
    try:
        document = json.loads(result.response_body[:2_000_000].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return tuple(sorted(signals))

    nodes: list[tuple[tuple[str, ...], dict]] = []
    scopes: set[tuple[str, ...]] = {()}
    token_names = {"token", "access_token", "id_token", "jwt"}

    def collect(value: Any, path: tuple[str, ...] = (), authenticated: bool = False) -> None:
        if len(path) > 8:
            return
        if isinstance(value, Mapping):
            fields = {_name(k): v for k, v in value.items()}
            nodes.append((path, fields))
            if path and path[-1] in _AUTH_ENVELOPES:
                scopes.add(path)  # also handles a header token with a nested auth verdict
            authenticated = authenticated or any(
                _flag(fields.get(k)) is True
                for k in {"authenticated", "is_authenticated", "logged_in", "is_logged_in"}
            )
            for name, child in fields.items():
                child_path = (*path, name)
                if (name in token_names and isinstance(child, str) and child.strip()
                        and not any(p in _CHALLENGE_ENVELOPES for p in path)
                        and (name != "token" or authenticated or any(p in _AUTH_ENVELOPES for p in path))):
                    signals.add("json:" + ".".join(child_path))
                    scopes.update(path[:i] for i in range(len(path) + 1))
                collect(child, child_path, authenticated)
        elif isinstance(value, list):
            for child in value[:20]:
                collect(child, (*path, "[]"), authenticated)

    collect(document)
    for path, fields in nodes:
        login_scoped = any(path[:i] in scopes and all(p in _LOGIN_SCOPE for p in path[i:])
                           for i in range(len(path) + 1))
        if not login_scoped:
            continue
        for name, child in fields.items():
            if (
                (name in _AUTH_FLAGS and _flag(child) is False)
                or (name in _REQUIRED_FLAGS and bool(child) and _flag(child) is not False)
                or (name in {"error", "errors", "error_description"} and bool(child))
                or (name in {"challenge", "captcha"} and not isinstance(child, Mapping)
                    and bool(child) and _flag(child) is not False)
                or (name in {"status", "state", "code", "error_code", "authentication_status",
                             "authentication_state", "login_status", "token_type", "purpose"}
                    and isinstance(child, str) and _name(child.strip()).replace(" ", "_") in _FAILED_STATES)
                or (name == "required" and any(p in _CHALLENGE_ENVELOPES for p in path)
                    and _flag(child) is True)
                or (name in token_names and any(p in _CHALLENGE_ENVELOPES for p in path) and bool(child))
            ):
                return ()
    return tuple(sorted(signals))
'''

TEMPLATE_HELPERS = '''def _pair_identity(node: Any) -> tuple[tuple[str, str], ...]:
    """Structural labels identify a name/value entry; positions do not."""
    if not isinstance(node, dict) or not any(k in node for k in _PAIR_VALUE_KEYS):
        return ()
    return tuple((k, node[k]) for k in _PAIR_NAME_KEYS
                 if isinstance(node.get(k), str) and node[k] != MASK)


def _field_sensitive(node: dict, key: str, inherited: bool) -> bool:
    # A parameter's `key` is its name, not its credential value. Keeping the label
    # visible also lets a masked editor round-trip/reorder entries unambiguously.
    if key in dict(_pair_identity(node)):
        return False
    return inherited or is_secret_field(key) or key in _secret_pair_values(node)


def _mask_node(node: Any, sensitive: bool = False) -> Any:
    if isinstance(node, dict):
        return {k: _mask_node(v, _field_sensitive(node, k, sensitive)) for k, v in node.items()}
    if isinstance(node, list):
        return [_mask_node(v, sensitive) for v in node]
    return MASK if sensitive and node not in (None, "") else node


def _restore(value: Any, existing: Any, sensitive: bool = False, old_sensitive: bool = False) -> Any:
    """Only a previously masked field of the same entry may retain a secret."""
    if sensitive and value == MASK:
        if existing is None or not old_sensitive:
            raise ValueError("Masked template value has no stored value to keep")
        return existing
    if isinstance(value, dict):
        old = existing if isinstance(existing, dict) else {}
        if _pair_identity(value) != _pair_identity(old):
            if any(value.get(k) == MASK for k in _secret_pair_values(old)):
                raise ValueError("Masked template entry was renamed; provide its value")
            old = {}
        return {k: _restore(v, old.get(k), _field_sensitive(value, k, sensitive),
                            _field_sensitive(old, k, old_sensitive)) for k, v in value.items()}
    if isinstance(value, list):
        previous = existing if isinstance(existing, list) else []
        restored = []
        for item in value:
            identity = _pair_identity(item)
            candidates = [old for old in previous if _pair_identity(old) == identity] if identity else [
                old for old in previous if _mask_node(old, old_sensitive) == item]
            # No positional fallback: duplicate names or indistinguishable masks
            # cannot establish which prior secret the operator intended to keep.
            old = candidates[0] if len(candidates) == 1 else None
            restored.append(_restore(item, old, sensitive, old_sensitive))
        return restored
    return value
'''

BACKUP = r'''    local key_file
    key_file="$(backup_key_file)"
    # Resolve key aliases before archiving, and verify actual member bytes afterwards.
    # tarfile does not dereference symlinks; inode checks also exclude hard-link aliases.
    if ! python3 - "$SCRIPT_DIR" "$key_file" "$snapshot_dir/results.tar.gz" "$include_key" <<'PY_BACKUP'
import hashlib
import os
from pathlib import Path
import sys
import tarfile

root, configured, output, include = Path(sys.argv[1]).resolve(), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] == "1"
paths = {root / "results" / ".credential_enc.key"}
paths.add(configured if configured.is_absolute() else root / configured)
if str(configured).startswith("/results/"):
    paths.add(root / str(configured).lstrip("/"))
inodes, key_hashes, key_names = set(), set(), {configured.name, ".credential_enc.key"}
try:
    if not include:
        for path in paths:
            if not path.exists() and not path.is_symlink():
                continue
            resolved = path.resolve(strict=True)
            info = resolved.stat()
            if not resolved.is_file() or info.st_size > 65536:
                raise ValueError("invalid credential key file")
            raw = resolved.read_bytes()
            inodes.add((info.st_dev, info.st_ino))
            key_hashes.add((len(raw), hashlib.sha256(raw).digest()))
            key_names.add(resolved.name)

    def secret_name(name):
        return name.startswith(".credential_enc.key") or any(
            name == key or name == key + ".lock" or name.startswith(key + ".tmp")
            for key in key_names)

    def keep(member):
        if include:
            return member
        if secret_name(Path(member.name).name):
            return None
        try:
            info = (root / member.name).stat()
        except FileNotFoundError:
            if member.issym():  # an unrelated broken symlink contains no key bytes
                return member
            raise
        return None if (info.st_dev, info.st_ino) in inodes else member

    with tarfile.open(output, "w:gz", dereference=False) as archive:
        archive.add(root / "results", arcname="results", filter=keep)
    if not include:
        key_sizes = {size for size, _ in key_hashes}
        with tarfile.open(output, "r:gz") as archive:
            for member in archive:
                if secret_name(Path(member.name).name):
                    raise ValueError("credential key member in backup")
                if member.isfile() and member.size in key_sizes:
                    with archive.extractfile(member) as stream:
                        if (member.size, hashlib.sha256(stream.read()).digest()) in key_hashes:
                            raise ValueError("credential key bytes in backup")
except Exception:
    output.unlink(missing_ok=True)
    print("Results backup failed or could not exclude the credential encryption key", file=sys.stderr)
    raise SystemExit(1)
PY_BACKUP
    then
        echo -e "${RED}Results backup failed. Partial files remain at $snapshot_dir${NC}"
        return 1
    fi
'''

REKEY_SQL = '''"""WITH prior AS MATERIALIZED (
                        SELECT id, target_id, fingerprint FROM findings WHERE id=$2 FOR UPDATE
                    ), moved AS (
                        UPDATE findings SET fingerprint=$1 WHERE id=$2 RETURNING id
                    )
                    UPDATE finding_exceptions AS exception
                    SET finding_id=prior.id::text, fingerprint=$1, updated_at=NOW(),
                        edit_history=COALESCE(exception.edit_history, '[]'::jsonb) || jsonb_build_array(
                            jsonb_build_object('transition', 'finding_identity_rekey',
                                              'fingerprint', exception.fingerprint,
                                              'finding_id', exception.finding_id,
                                              'replaced_at', NOW()))
                    FROM prior, moved
                    WHERE moved.id=prior.id AND exception.target_id=prior.target_id
                      AND exception.fingerprint=prior.fingerprint
                      AND (NULLIF(exception.finding_id, '') IS NULL OR exception.finding_id=prior.id::text)
                    """'''


def apply():
    verify()
    function('api/capabilities/authentication_proof.py', 'successful_token_signals', AUTH)
    function('api/runtime/ai_template_secrets.py', '_restore', TEMPLATE_HELPERS)
    function('api/runtime/ai_template_secrets.py', 'public', '''def public(value: Any) -> dict:
    return _mask_node(reveal(value))''')
    replace('api/api.py', '''        try:  # an exception recorded under an earlier identity of this finding still applies
            fingerprints = {str(finding.get("fingerprint") or ""), *finding_identity_keys(finding)}
        except Exception:
            fingerprints = {str(finding.get("fingerprint") or "")}
''', '''        # Historical hashes omit service/route/check provenance and are not authority.
        # Reconciliation binds a legacy exception to the actual row during its re-key.
        fingerprints = {str(finding.get("fingerprint") or ""), canonical_finding_fingerprint(finding)}
''')
    replace('api/api.py', '''        if fingerprint:
            active_fingerprints.add(fingerprint)
''', '''        if fingerprint and not item.get("finding_id"):
            active_fingerprints.add(fingerprint)
''')
    replace('api/scan/finding_reconciliation.py', '"UPDATE findings SET fingerprint = $1 WHERE id = $2"', REKEY_SQL)
    p = ROOT / 'scanner.sh'
    text = p.read_text()
    start = text.index('    local key_file key_name\n', text.index('create_backup() {'))
    end = text.index('\n    if [ -f "$SCRIPT_DIR/.env" ]; then', start)
    p.write_text(text[:start] + BACKUP + text[end:])
    # Characterize an exception bound to the migrated row, not an ambiguous bare alias.
    replace('tests/test_deployment_gate.py', '''    exception = {"id": "e1", "fingerprint": earlier, "status": "active", "approver": "a",
''', '''    exception = {"id": "e1", "finding_id": "r1", "fingerprint": earlier, "status": "active", "approver": "a",
''')
    replace('tests/test_deployment_gate.py', '''    unrelated = {**exception, "fingerprint": "t:0000000000000000"}
''', '''    unrelated = {**exception, "finding_id": "other-row", "fingerprint": "t:0000000000000000"}
''')
    replace('tests/test_finding_service_identity.py', '''CREATE TABLE finding_verifications(
''', '''CREATE TABLE finding_exceptions(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), finding_id text, fingerprint text, target_id uuid,
 updated_at timestamptz, edit_history jsonb DEFAULT '[]', status text, approver text, expires_at timestamptz);
CREATE TABLE finding_verifications(
''')
    add_tests()
    for name in ['api/api.py', 'api/capabilities/authentication_proof.py', 'api/runtime/ai_template_secrets.py',
                 'api/scan/finding_reconciliation.py']:
        ast.parse((ROOT / name).read_text(), filename=name)


def add_tests():
    append('tests/test_authentication_proof_contract.py', r'''
@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("wrapper", ["loginResult", "customEnvelope", "vendorReply"])
@pytest.mark.parametrize("failure", [{"authenticated": False}, {"status": "mfa_required"}, {"requires_mfa": True}])
def test_unknown_wrappers_do_not_hide_a_tokens_own_failed_authentication(family, wrapper, failure):
    response = {wrapper: {"authentication": {"token": "stage-canary", **failure}}}
    result = _run(family, response, token_header=True)
    assert result.observations[0]["proof_state"] == "not_proven"
    assert result.observations[0]["proof_contract"] is None
    assert "stage-canary" not in json.dumps(result.__dict__, default=str)


@pytest.mark.parametrize("family", ["sql", "nosql"])
def test_unknown_wrapper_failure_along_the_token_ancestry_vetoes_bypass(family):
    result = _run(family, {"loginResult": {"requiresMfa": True, "authentication": {"token": "stage-canary"}}})
    assert result.observations[0]["proof_state"] == "not_proven"


@pytest.mark.parametrize("family", ["sql", "nosql"])
def test_successful_unknown_wrapper_ignores_unrelated_metadata(family):
    result = _run(family, {"loginResult": {"authentication": {"token": "login-canary"}},
                          "user": {"verification": {"required": True}, "subscription": {"status": "failed"}}})
    assert result.observations[0]["proof_state"] == "verified"
''')
    append('tests/test_ai_template_secrets.py', r'''
@pytest.mark.parametrize("change", ["reverse", "delete_first"])
def test_masked_named_entries_keep_their_own_values_after_reorder_or_removal(key, change):
    template = {"headers": [{"name": "Authorization", "value": "Bearer first-canary"},
                            {"name": "X-Session-Token", "value": "second-canary"}]}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    shown["headers"] = list(reversed(shown["headers"])) if change == "reverse" else shown["headers"][1:]
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    values = {item["name"]: item["value"] for item in restored["headers"]}
    assert values["X-Session-Token"] == "second-canary"
    if change == "reverse":
        assert values["Authorization"] == "Bearer first-canary"


@pytest.mark.parametrize("name", ["X-Debug", "X-Other-Token"])
def test_renaming_a_masked_entry_never_inherits_the_previous_secret(key, name):
    stored = ai_template_secrets.protect({"header": {"name": "Authorization", "value": "Bearer rename-canary"}})
    shown = ai_template_secrets.public(stored)
    shown["header"]["name"] = name
    with pytest.raises(ValueError, match="Masked"):
        ai_template_secrets.protect(shown, stored)
    shown["header"]["value"] = "explicit-replacement"
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["header"]["value"] == "explicit-replacement"
    assert "rename-canary" not in json.dumps(ai_template_secrets.public(stored))


def test_duplicate_named_masks_are_ambiguous_but_explicit_values_are_editable(key):
    template = {"headers": [{"name": "Authorization", "value": value} for value in ("first-canary", "second-canary")]}
    stored = ai_template_secrets.protect(template)
    with pytest.raises(ValueError, match="Masked"):
        ai_template_secrets.protect(ai_template_secrets.public(stored), stored)
    assert ai_template_secrets.reveal(ai_template_secrets.protect(template, stored)) == template


def test_parameter_labels_remain_visible_and_survive_reordering(key):
    template = {"params": [{"key": "client_assertion", "val": "assertion-canary"},
                           {"key": "api_key", "val": "api-canary"}]}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    assert shown["params"][0]["key"] == "client_assertion"
    shown["params"].reverse()
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["params"] == list(reversed(template["params"]))
''')
    append('tests/test_deployment_gate.py', r'''
def test_legacy_exception_aliases_never_expand_across_services_routes_or_checks():
    import hashlib
    from findings import pre_service_templated_finding_identity, pre_check_templated_finding_identity
    base = {"id": "first", "title": "SQL Injection", "severity": "critical", "tool": "sqlmap",
            "cwe": "CWE-89", "url": "https://app.example.test/search?q=1", "evidence": {"method": "GET", "param": "q"}}
    dom = {**base, "cwe": "CWE-79", "evidence": {"param": "q", "client_route": "/search?q=1"}}
    tls = {**base, "cwe": "CWE-295", "url": "https://app.example.test/", "evidence": {"check": "untrusted"}}
    pairs = [
        (base, {**base, "id": "second", "url": "https://app.example.test:8443/search?q=1"}, pre_service_templated_finding_identity),
        (dom, {**dom, "id": "second", "evidence": {"param": "q", "client_route": "/profile?q=1"}}, pre_service_templated_finding_identity),
        (tls, {**tls, "id": "second", "evidence": {"check": "expired"}}, pre_check_templated_finding_identity),
    ]
    for first, second, historical in pairs:
        first["fingerprint"] = canonical_finding_fingerprint(first)
        second["fingerprint"] = canonical_finding_fingerprint(second)
        assert first["fingerprint"] != second["fingerprint"]
        alias = "t:" + hashlib.sha256(historical(first).encode()).hexdigest()[:16]
        exception = {"id": "exception", "fingerprint": alias, "status": "active", "approver": "operator",
                     "expires_at": "2099-01-01T00:00:00Z"}
        remaining, applied = api._apply_policy_exceptions([first, second], [exception])
        assert remaining == [first, second] and applied == []
        remaining, applied = api._apply_policy_exceptions([first, second], [{**exception, "finding_id": "first"}])
        assert remaining == [second] and applied == [first]
''')
    append('tests/test_backup_secrets_and_retention.py', r'''
@pytest.mark.parametrize("custom", [False, True])
def test_symlink_and_hardlink_key_aliases_never_enter_an_excluded_key_backup(tmp_path, custom):
    install = _install(tmp_path)
    results = install / "results"
    original = results / ".credential_enc.key"
    original.unlink()
    backing = results / "keys" / "actual.fernet"
    backing.parent.mkdir()
    backing.write_text("synthetic-key-canary\n")
    configured = results / "custom.fernet" if custom else original
    configured.symlink_to("keys/actual.fernet")
    (results / "renamed-hardlink").hardlink_to(backing)
    result = _run(install, "create_backup", AI_CREDENTIAL_ENC_KEY_FILE=str(configured))
    assert result.returncode == 0, result.stderr
    backup = _only_backup(install)
    with tarfile.open(backup / "results.tar.gz") as archive:
        assert "results/scan.json" in archive.getnames()
        assert not {"results/keys/actual.fernet", "results/renamed-hardlink", "results/custom.fernet", "results/.credential_enc.key"} & set(archive.getnames())
    assert "encryption_key_included=false" in (backup / "manifest.txt").read_text()


def test_custom_key_rotation_files_are_excluded_too(tmp_path):
    install = _install(tmp_path)
    key = install / "results" / "custom.fernet"
    key.write_text("custom-key-canary")
    key.with_name(key.name + ".tmp.123").write_text("partial-key-canary")
    result = _run(install, "create_backup", AI_CREDENTIAL_ENC_KEY_FILE=str(key))
    assert result.returncode == 0, result.stderr
    with tarfile.open(_only_backup(install) / "results.tar.gz") as archive:
        assert not any("custom.fernet" in name for name in archive.getnames())
''')
    append('tests/test_finding_service_identity.py', r'''
def test_postgres_rekey_binds_only_the_original_rows_exception_atomically():
    async def run():
        async with _database() as conn:
            target, other_target = uuid.uuid4(), uuid.uuid4()
            await conn.execute("INSERT INTO targets(id) VALUES($1),($2)", target, other_target)
            finding = _finding("https://example.test/search?q=1")
            old_key = "t:" + hashlib.sha256(pre_service_templated_finding_identity(finding).encode()).hexdigest()[:16]
            canonical = canonical_finding_fingerprint(finding)
            row_id = await conn.fetchval("""INSERT INTO findings(target_id,fingerprint,title,url,tool,cwe,evidence,status)
                VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,'accepted_risk') RETURNING id""", target, old_key,
                finding["title"], finding["url"], finding["tool"], finding["cwe"], json.dumps(finding["evidence"]))
            exception_id = await conn.fetchval("""INSERT INTO finding_exceptions(target_id,fingerprint,status,approver,expires_at)
                VALUES($1,$2,'active','operator','2099-01-01') RETURNING id""", target, old_key)
            other_id = await conn.fetchval("""INSERT INTO finding_exceptions(target_id,fingerprint,status,approver,expires_at)
                VALUES($1,$2,'active','operator','2099-01-01') RETURNING id""", other_target, old_key)
            async with conn.transaction():
                adopted = await reconcile_legacy_finding_row(conn, target_uuid=target, fingerprint=canonical, finding=finding)
            assert adopted["id"] == row_id
            saved = await conn.fetchrow("SELECT * FROM finding_exceptions WHERE id=$1", exception_id)
            assert saved["finding_id"] == str(row_id) and saved["fingerprint"] == canonical
            assert saved["status"] == "active" and saved["approver"] == "operator" and saved["expires_at"].year == 2099
            assert json.loads(saved["edit_history"])[0]["fingerprint"] == old_key
            untouched = await conn.fetchrow("SELECT * FROM finding_exceptions WHERE id=$1", other_id)
            assert untouched["fingerprint"] == old_key and untouched["finding_id"] is None
    asyncio.run(run())
''')


if __name__ == '__main__':
    apply()
