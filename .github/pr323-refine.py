"""Preserve pre-existing secret classifications while binding masked pair names."""
from pathlib import Path
import importlib.util
import subprocess

for name in ('api/runtime/ai_template_secrets.py', 'tests/test_ai_template_secrets.py'):
    expected = subprocess.check_output(['git', 'rev-parse', '46b37dd6b73a568c09ba395e32c258c6e6a0bc0a:' + name])
    actual = subprocess.check_output(['git', 'hash-object', name])
    if actual != expected:
        raise RuntimeError('Refusing to overwrite changed source: ' + name)

spec = importlib.util.spec_from_file_location('repair', Path('.github/pr323-repair.py'))
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)
repair.function('api/runtime/ai_template_secrets.py', '_field_sensitive', '''def _field_sensitive(node: dict, key: str, inherited: bool) -> bool:
    # A field called `key` may contain credential material, not a parameter name.
    # Entry matching must never lower the existing masking classification.
    return inherited or is_secret_field(key) or key in _secret_pair_values(node)


def _matching_pair_identity(value: dict, existing: dict, sensitive: bool, old_sensitive: bool) -> tuple:
    labels = dict(value)
    for key in _PAIR_NAME_KEYS:
        if (value.get(key) == MASK and isinstance(existing.get(key), str)
                and _field_sensitive(value, key, sensitive)
                and _field_sensitive(existing, key, old_sensitive)):
            labels[key] = existing[key]
    return _pair_identity(labels)''')
repair.replace('api/runtime/ai_template_secrets.py',
    '        if _pair_identity(value) != _pair_identity(old):',
    '        if _matching_pair_identity(value, old, sensitive, old_sensitive) != _pair_identity(old):')
repair.replace('api/runtime/ai_template_secrets.py',
    '            candidates = [old for old in previous if _pair_identity(old) == identity] if identity else [',
    '            candidates = [old for old in previous if isinstance(old, dict) and\n'
    '                _matching_pair_identity(item, old, sensitive, old_sensitive) == _pair_identity(old)] if identity else [')
repair.replace('api/runtime/ai_template_secrets.py',
    '        return {k: _restore(v, old.get(k), _field_sensitive(value, k, sensitive),',
    '        return {k: _restore(v, old.get(k), _field_sensitive(value, k, sensitive) or k in _secret_pair_values(old),')
# `name` is a public entry label; `key` retains the conservative existing masking rule.
repair.function('tests/test_ai_template_secrets.py', 'test_parameter_labels_remain_visible_and_survive_reordering', '''def test_public_parameter_labels_survive_reordering(key):
    template = {"params": [{"name": "client_assertion", "val": "assertion-canary"},
                           {"name": "api_key", "val": "api-canary"}]}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    assert shown["params"][0]["name"] == "client_assertion"
    shown["params"].reverse()
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["params"] == list(reversed(template["params"]))''')
repair.append('tests/test_ai_template_secrets.py', '''def test_pair_detection_never_unmasks_previously_secret_fields(key):
    template = {"credentials": [{"key": "actual-key-canary", "value": "other-canary"}],
                "pair": {"key": "actual-second-canary", "value": 42}}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    assert "canary" not in json.dumps(shown)
    assert ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored)) == template


def test_uniquely_masked_parameter_labels_keep_their_values_after_reorder(key):
    template = {"params": [{"key": "client_assertion", "val": "assertion-canary"},
                           {"key": "page", "val": "2"}]}
    stored = ai_template_secrets.protect(template)
    shown = ai_template_secrets.public(stored)
    assert shown["params"][0]["key"] == "***"
    shown["params"].reverse()
    restored = ai_template_secrets.reveal(ai_template_secrets.protect(shown, stored))
    assert restored["params"] == list(reversed(template["params"]))


@pytest.mark.parametrize("name", ["X-Debug", "X-Other-Token"])
def test_renamed_masked_list_entries_never_disclose_or_move_a_secret(key, name):
    stored = ai_template_secrets.protect({"headers": [{"name": "Authorization", "value": "Bearer list-canary"}]})
    shown = ai_template_secrets.public(stored)
    shown["headers"][0]["name"] = name
    try:
        updated = ai_template_secrets.protect(shown, stored)
    except ValueError:
        return
    assert "list-canary" not in json.dumps(ai_template_secrets.reveal(updated))
    assert "list-canary" not in json.dumps(ai_template_secrets.public(updated))''')
