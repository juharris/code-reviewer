import re
from typing import Collection, Optional, TypedDict

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
	# Checks (in alphabetical order)
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
	source_ref_name_pattern: Optional[str]
	source_ref_name_regex: Optional[re.Pattern]
	target_ref_name_pattern: Optional[str]
	target_ref_name_regex: Optional[re.Pattern]
	title_pattern: Optional[str]
	title_regex: Optional[re.Pattern]

	# Actions (in alphabetical order)
	add_tags: Optional[list[str]]
	"""
	Tags to add to the pull request.
	"""

	comment: Optional[str]
	"""
	The comment to post on the pull request or the the line if `diff_pattern` is set.
	"""

	comment_id: Optional[str]
	"""
	An ID to use to identify the comment.
	A comment ID is appended as a HTML comment within the comment.
	If this is set, then before posting a new comment,
	there will be a search for a comment with this ID by the current user.
	If a comment is found,
	then the thread with this comment will be reactivated (if necessary)
	and the comment will be edited (if necessary).
	"""

	new_title: Optional[str]
	require: Optional[str | Collection[str]]
	requeue: Optional[list[JsonPathCheck]]
	"""
	Checks for a policy to try to re-queue.
	"""
	requeue_comment: Optional[str]
	"""
	Comment to post when re-queueing.
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