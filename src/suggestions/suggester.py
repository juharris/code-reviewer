from typing import Optional
import re

from config import Rule

from . import SuggestedChange, SuggestedChanges



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
		while True:
			found_matches = False
			for suggestion_config in suggestions:
				p = suggestion_config['pattern_regex']
				while p.match(suggestion):
					replacement = suggestion_config['replacement']
					suggestion = p.sub(replacement, suggestion)
					is_change_made = found_matches = True
			if not found_matches:
				break

		if is_change_made:
			return SuggestedChange(suggestion)
		else:
			return None