import re
from typing import Optional, TypedDict


# TODO Add more fields.
class Rule(TypedDict):
	author_pattern: Optional[str]
	author_regex: Optional[re.Pattern]
	description_pattern: Optional[str]
	description_regex: Optional[re.Pattern]
	diff_pattern: Optional[str]
	diff_regex: Optional[re.Pattern]
	title_pattern: Optional[str]
	title_regex: Optional[re.Pattern]

# TODO Add more fields.
class Config(TypedDict):
	organization_url: str
	project: str
	repository_name: str
	top: int
	rules: list[Rule]

	PAT: Optional[str]
	# TODO Try to automate getting the current user from the PAT.
	current_user: Optional[str]
	user_id: Optional[str]