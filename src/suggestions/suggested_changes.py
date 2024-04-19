from dataclasses import dataclass


@dataclass
class SuggestedChange:
	suggestion: str

@dataclass
class SuggestedChanges:
	suggestions: list[SuggestedChange]