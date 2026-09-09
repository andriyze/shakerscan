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
