"""The publication guard must not exclude arbitrary test files or print secrets."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('hygiene', Path(__file__).resolve().parents[1] / 'scripts/check_public_repo_hygiene.py')
hygiene = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hygiene)


def test_operator_paths_and_environments_are_not_publishable():
    for path in ['results/raw.json', 'exports/all.json', 'captures/site.har', '.env', '.env.production', '.claude/settings.local.json', 'snapshot.sqlite3']:
        assert hygiene.violations(path, b'{}')
    for path in ['.env.example', 'tests/fixtures/synthetic.har', 'docs/results-guide.md']:
        assert not hygiene.violations(path, b'{}')


def test_only_exact_reviewed_aws_sample_is_allowed_in_tests():
    sample = b'AKIA' + b'IOSFODNN7EXAMPLE'
    assert not hygiene.violations('tests/test_detector.py', sample)
    assert hygiene.violations('app.py', sample)
    assert hygiene.violations('tests/new_test.py', b'AKIA' + b'Q' * 16)


def test_secrets_are_detected_without_echoing_values():
    for value in [b'ghp_' + b'z' * 36, b'github_pat_' + b'z' * 70, b'sk-proj-' + b'z' * 55]:
        messages = hygiene.violations('tests/example.py', b'first line\n' + value)
        assert messages and ':2:' in messages[0]
        assert value.decode() not in ' '.join(messages)


def test_private_key_header_fixture_is_not_a_private_key():
    header = b'-----BEGIN ' + b'PRIVATE KEY-----'
    assert not hygiene.violations('tests/detector.py', header)
    assert hygiene.violations('src/config.py', header + b'\n' + b'A' * 120 + b'\n')
