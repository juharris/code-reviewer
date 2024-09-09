"""
Helps check JSON Paths.
"""

from dataclasses import dataclass
import logging
from injector import inject

from config import JsonPathCheck, JsonPathChecks, MatchType


@inject
@dataclass
class MatcherChecker:
    """
    Checks JSON Paths.
    """
    logger: logging.Logger

    def check_matchers(self,
                          matchers: list[JsonPathChecks],
                          pr_as_dict: dict) -> bool:
        """
        :returns: `True` if all checks match; otherwise, `False`.
        """
        result = True
        for matcher in matchers:
            checks = matcher['checks']
            result = any(self.is_check_match(check, pr_as_dict) for check in checks)
            match_type = matcher['match_type']
            if match_type == MatchType.NOT_ANY:
                result = not result
            if not result:
                break

        return result

    def is_check_match(self, check: JsonPathCheck, data: dict) -> bool:
        """
        :returns: `True` if the check matches the data; otherwise, `False`.
        """
        matches = check['json_path_'].search(data)
        if matches is None or len(matches) == 0:
            return False
        self.logger.debug("JSON Path '%s' matches: %s", check['json_path'], matches)
        if (pat := check.get('regex')) is not None:
            # `None` can be in matches maybe when a value such as a status is not set?
            return any(m is not None and pat.match(str(m)) for m in matches)
        return True
