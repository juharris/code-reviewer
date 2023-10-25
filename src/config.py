import re
from typing import Optional, TypedDict

from jsonpath import JSONPath


class JsonPathCheck(TypedDict):
	"""
	A generic way to check if a dictionary matches a check.
	"""
	json_path: str
	json_path_: JSONPath
	pattern: Optional[str]
	regex: Optional[re.Pattern]


class PolicyEvaluationChecks(TypedDict):
	evaluation_checks: list[JsonPathCheck]


class Rule(TypedDict):
	# Checks
	author_pattern: Optional[str]
	author_regex: Optional[re.Pattern]
	description_pattern: Optional[str]
	description_regex: Optional[re.Pattern]
	diff_pattern: Optional[str]
	diff_regex: Optional[re.Pattern]
	is_draft: Optional[bool]
	path_pattern: Optional[str]
	path_regex: Optional[re.Pattern]
	policy_checks: Optional[list[PolicyEvaluationChecks]]
	title_pattern: Optional[str]
	title_regex: Optional[re.Pattern]

	# Actions
	add_tags: Optional[list[str]]
	comment: Optional[str]
	new_title: Optional[str]
	require: Optional[str]
	requeue: Optional[list[JsonPathCheck]]
	"""
	Checks for a policy to try to re-queue.
	"""
	vote: Optional[int | str]


class Config(TypedDict):
	organization_url: str
	project: str
	repository_name: str
	top: int
	rules: list[Rule]
	unique_path_regexs: set[re.Pattern]

	PAT: Optional[str]
	current_user: Optional[str]
	user_id: Optional[str]

	is_stats_enabled: Optional[bool]