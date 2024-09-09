from injector import Injector

from config import ConfigLoader, JsonPathCheck
from matcher_checker import MatcherChecker
from logger import LoggingModule
from voting import APPROVE_VOTE, NO_VOTE


def test_is_check_match():
    inj = Injector([LoggingModule])
    matcher_checker = inj.get(MatcherChecker)
    data = {
        "reviewers": [
            {
                "display_name": "Name",
                "unique_name": "email",
                "vote": NO_VOTE,
            },
            {
                "display_name": "Name 2",
                "unique_name": "email2",
                "vote": APPROVE_VOTE,
            },
        ]
    }
    matching_check: JsonPathCheck = {
        'json_path': '$.reviewers[*].display_name',
        'pattern': '^Name$',
    }
    ConfigLoader.init_json_path_check(matching_check)
    assert matcher_checker.is_check_match(matching_check, data)

    not_matching_check: JsonPathCheck = {
        'json_path': '$.reviewers[*].display_name',
        'pattern': '^dude$',
    }
    ConfigLoader.init_json_path_check(not_matching_check)
    assert not matcher_checker.is_check_match(not_matching_check, data)

    matching_check: JsonPathCheck = {
        'json_path': '$.reviewers[?(@.unique_name== "email")].vote',
        'pattern': f'^{NO_VOTE}$',
    }
    ConfigLoader.init_json_path_check(matching_check)
    assert matcher_checker.is_check_match(matching_check, data)

    not_matching_check: JsonPathCheck = {
        'json_path': '$.reviewers[?(@.unique_name== "email")].vote',
        'pattern': '^7$',
    }
    ConfigLoader.init_json_path_check(not_matching_check)
    assert not matcher_checker.is_check_match(not_matching_check, data)
