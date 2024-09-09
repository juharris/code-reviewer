import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from injector import inject
import requests
import yaml
from jsonpath import JSONPath

from suggestions import Suggester
from voting import map_vote
from .config import (ATTRIBUTES_WITH_PATTERNS, DEFAULT_MAX_REQUEUES_PER_RUN,
                     Config, JsonPathCheck, JsonPathChecks, MatchType, RequeueConfig)


@dataclass
class ConfigLoadInfo:
    config: Config
    is_fresh: bool


@inject
@dataclass
class ConfigLoader:
    config_source: str
    logger: logging.Logger

    config: Config = field(init=False)
    config_hash: Optional[str] = field(default=None, init=False)

    def load_config(self) -> ConfigLoadInfo:
        is_fresh = False
        config_contents: Optional[str] = None
        if self.config_source.startswith('https://') or self.config_source.startswith('http://'):
            max_num_tries = 3
            for try_num in range(max_num_tries):
                try:
                    r = requests.get(self.config_source)
                    r.raise_for_status()
                    config_contents = r.text
                    break
                except BaseException:
                    if try_num == max_num_tries - 1:
                        raise
                    self.logger.exception(f"Error while downloading config from '{self.config_source}'.")
                    time.sleep(1 + try_num * 2)
        else:
            with open(self.config_source, 'r', encoding='utf-8') as f:
                config_contents = f.read()

        assert config_contents is not None
        config_hash = hashlib.sha256(config_contents.encode('utf-8')).hexdigest()
        if config_hash != self.config_hash:
            self.logger.info("Loading configuration from '%s'.", self.config_source)
            config: Config = yaml.safe_load(config_contents)

            log_level = logging.getLevelName(config.get('log_level', 'INFO') or 'INFO')
            self.logger.setLevel(log_level)

            limit = config.get('same_comment_per_PR_per_run_limit')
            if limit is None:
                # Match documented limit.
                config['same_comment_per_PR_per_run_limit'] = 20

            requeue_config = config.get('requeue_config')
            if requeue_config is None:
                requeue_config = RequeueConfig(max_per_run=DEFAULT_MAX_REQUEUES_PER_RUN)
                config['requeue_config'] = requeue_config
            else:
                if requeue_config.get('max_per_run') is None:
                    requeue_config['max_per_run'] = DEFAULT_MAX_REQUEUES_PER_RUN

            reset_votes_after_changes = config.get('reset_votes_after_changes')
            if reset_votes_after_changes is not None:
                assert isinstance(
                    reset_votes_after_changes, list), f"reset_votes_after_changes must be a list. Got: {reset_votes_after_changes} with type: {type(reset_votes_after_changes)}"
                reset_votes_after_changes = set(map_vote(vote) for vote in reset_votes_after_changes)
                assert all(
                    vote is not None for vote in reset_votes_after_changes), f"reset_votes_after_changes must be a list of integers. Got: {reset_votes_after_changes}"
                config['reset_votes_after_changes'] = reset_votes_after_changes  # type: ignore

            rules = config['rules']
            for rule in rules:
                for name in ('author',) + ATTRIBUTES_WITH_PATTERNS:
                    if pat := rule.get(f'{name}_pattern'):
                        rule[f'{name}_regex'] = re.compile(pat, re.DOTALL)  # type: ignore
                if (pat := rule.get('diff_pattern')) is not None:
                    rule['diff_regex'] = re.compile(pat, re.DOTALL)
                if (pat := rule.get('path_pattern')) is not None:
                    rule['path_regex'] = re.compile(pat)

                vote = rule.get('vote')
                if isinstance(vote, str):
                    rule['vote'] = map_vote(vote)

                if (matchers := rule.get('matchers')) is not None:
                    self.init_matchers(matchers)

                if (rule_policy_checks := rule.get('policy_checks')) is not None:
                    for rule_policy_check in rule_policy_checks:
                        for evaluation_check in rule_policy_check['evaluation_checks']:
                            evaluation_check['json_path_'] = JSONPath(evaluation_check['json_path'])
                            if (pat := evaluation_check.get('pattern')) is not None:
                                evaluation_check['regex'] = re.compile(pat)
                        if (match_type := rule_policy_check.get('match_type')) is None:
                            rule_policy_check['match_type'] = MatchType.ANY
                        else:
                            rule_policy_check['match_type'] = MatchType(match_type)

                if (requeue := rule.get('requeue')) is not None:
                    for check in requeue:
                        check['json_path_'] = JSONPath(check['json_path'])
                        if (pat := check.get('pattern')) is not None:
                            check['regex'] = re.compile(pat)

                Suggester.load_suggestions(rule)

            self.config = config
            is_fresh = True
            self.config_hash = config_hash

            self.logger.info("Loaded configuration with %d rule(s).", len(rules))
        return ConfigLoadInfo(self.config, is_fresh)

    @staticmethod
    def init_matchers(matchers: list[JsonPathChecks]) -> None:
        """
        Initialize the JSON Path checks.
        """
        for matcher in matchers:
            for check in matcher['checks']:
                ConfigLoader.init_json_path_check(check)
            if (match_type := matcher.get('match_type')) is None:
                matcher['match_type'] = MatchType.ANY
            else:
                matcher['match_type'] = MatchType(match_type)

    @staticmethod
    def init_json_path_check(check: JsonPathCheck) -> None:
        """
        Initialize the JSON Path check.
        """
        check['json_path_'] = JSONPath(check['json_path'])
        if (pat := check.get('pattern')) is not None:
            check['regex'] = re.compile(pat)
