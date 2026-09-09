from scripts.summarize_e2e_debt import summarize
import pytest


def test_accepted_failures_are_not_counted_as_actual_passes():
    result = summarize({'gate':'pass', 'areas':[{'area':'fixture','rows':[
        {'name':'pass','passed':True},
        {'name':'xfail','passed':True,'xfail':True,'xpass':False,'detail':'must not copy'},
        {'name':'xpass','passed':True,'xfail':True,'xpass':True},
        {'name':'skip','passed':True,'skipped':True},
    ]}]})
    assert result['counts'] == {'passed':2,'failed':1,'skipped':1,'unknown':0,
                                'accepted_failures':1,'unexpected_failures':0,'debt_xpasses':1}
    assert result['policy_gate'] == 'pass'
    assert result['assertions_clean'] is False
    assert 'detail' not in str(result)


def test_missing_xpass_is_unknown_not_assumed_success():
    result = summarize({'areas':[{'rows':[{'passed':True,'xfail':True}]}]})
    assert result['counts']['unknown'] == 1
    assert result['counts']['passed'] == 0


def test_ordinary_failure_is_unexpected():
    result = summarize({'areas':[{'rows':[{'passed':False}]}]})
    assert result['counts']['unexpected_failures'] == 1


@pytest.mark.parametrize('card', [{}, {'areas':[{}]}])
def test_invalid_scorecard_is_rejected(card):
    with pytest.raises(ValueError):
        summarize(card)


@pytest.mark.parametrize('card', [
    {'gate':'FAIL', 'areas':[]},
    {'gate':'pass','areas':[]},
    {'gate':'pass','areas':[{'area':'dast','rows':[]}]},
    {'gate':'pass','areas':[{'area':'dast','rows':[{'name':'optional','passed':True,'skipped':True}]}]},
])
def test_empty_or_skipped_only_is_not_validated(card):
    result = summarize(card)
    assert not result['assertions_clean']
    assert not result['validation_complete']
    assert not result['policy_validated']


def test_failed_upstream_gate_cannot_be_overridden_by_clean_rows():
    result = summarize({'gate':'FAIL','areas':[{'area':'dast','rows':[{'name':'one','passed':True}]}]})
    assert result['observed_assertions_clean'] is True
    assert result['policy_validated'] is False
    assert result['assertions_clean'] is False


def test_missing_required_area_or_skipped_required_assertion_fails():
    card = {'gate':'pass','areas':[{'area':'dast','rows':[
        {'name':'baseline','passed':True}, {'name':'required','passed':True,'skipped':True}]}]}
    assert not summarize(card, required_areas=['dast','hunt'])['policy_validated']
    assert not summarize(card, required_checks=['dast:required'])['policy_validated']
    assert summarize(card, required_checks=['dast:baseline'])['policy_validated']


def test_optional_skip_does_not_fail_real_completed_validation():
    result = summarize({'gate':'pass','areas':[{'area':'dast','gate':'pass','rows':[
        {'name':'baseline','passed':True}, {'name':'optional','passed':True,'skipped':True}]}]})
    assert result['assertions_clean'] and result['policy_validated']


def test_duplicate_areas_do_not_satisfy_completeness():
    area = {'area':'dast','rows':[{'name':'baseline','passed':True}]}
    assert not summarize({'gate':'pass','areas':[area,area]})['policy_validated']


@pytest.mark.parametrize('strict,expected', [(False,0),(True,1)])
def test_cli_accepts_explicit_debt_only_in_nonstrict_complete_validation(tmp_path, strict, expected):
    import json, subprocess, sys
    from pathlib import Path
    path = tmp_path/'card.json'
    path.write_text(json.dumps({'gate':'pass','areas':[{'area':'dast','gate':'pass','rows':[
        {'name':'baseline','passed':True}, {'name':'debt','passed':True,'xfail':True,'xpass':False}]}]}))
    script = Path(__file__).resolve().parents[1]/'scripts/summarize_e2e_debt.py'
    command = [sys.executable,str(script),str(path),'--require-area','dast'] + (['--strict'] if strict else [])
    result = subprocess.run(command,capture_output=True,text=True)
    assert result.returncode == expected
    assert json.loads(result.stdout)['counts']['accepted_failures'] == 1
