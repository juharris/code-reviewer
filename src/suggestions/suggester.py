import re
from typing import Optional

from config import Rule

from . import SuggestedChange


class Suggester:
    @classmethod
    def load_suggestions(cls, rule: Rule) -> None:
        if (suggestions := rule.get('suggestions')) is not None:
            for suggestion in suggestions:
                suggestion['pattern_regex'] = re.compile(suggestion['pattern'])

    def get_suggestion(self, text: str, rule: Rule) -> str:
        suggestion = self.suggest(text, rule)
        if suggestion is None:
            return ""
        else:
            return f"\n\n```suggestion\n{suggestion.suggestion}\n```"

    def suggest(self, text: str, rule: Rule) -> Optional[SuggestedChange]:
        suggestions = rule.get('suggestions')
        if suggestions is None:
            return None

        is_change_made = False
        suggestion = text

        # Keep applying suggestions until no more changes are made.
        # Limit looping to prevent infinite loops.
        loop_limit = 10
        loop_count = 0
        inner_loop_count = 0
        while loop_count < loop_limit:
            loop_count += 1
            found_matches = False
            for suggestion_config in suggestions:
                p = suggestion_config['pattern_regex']
                replacement = suggestion_config['replacement']
                inner_loop_count = 0
                while inner_loop_count < loop_limit:
                    inner_loop_count += 1
                    suggestion, num_substitutions = p.subn(replacement, suggestion)
                    if num_substitutions > 0:
                        is_change_made = found_matches = True
                    else:
                        break
            if not found_matches:
                break

        if is_change_made:
            return SuggestedChange(suggestion)
        else:
            return None
