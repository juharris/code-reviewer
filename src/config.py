import re
from enum import Enum
from typing import Collection, Optional, TypedDict

from jsonpath import JSONPath

DEFAULT_MAX_REQUEUES_PER_RUN = 10


class RequeueConfig(TypedDict):
	max_per_run: Optional[int]
	"""
	The maximum number of re-queues to perform in a single run across all rules for all pull requests.
	Defaults to 10.
	"""


class MatchType(Enum):
	"""
	How the checks combination of the checks should be evaluated.
	"""

	ANY = "any"
	"""
	At least one of the checks should match.
	"""

	NOT_ANY = "not_any"
	"""
	None of the checks should match.
	"""


class JsonPathCheck(TypedDict):
	"""
	A generic way to check if a dictionary matches a check.
	"""
	json_path: str
	json_path_: JSONPath
	pattern: Optional[str]
	regex: Optional[re.Pattern]


class PolicyEvaluationChecks(TypedDict):
	match_type: MatchType
	"""
	Determines how the checks combination of the checks should be evaluated.
	"""
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
	add_optional_reviewers: Optional[list[str]]
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

	comment_limit: Optional[int]
	"""
	The maximum number of times the `comment` can be posted on a pull request in one run of the script.
	Overrides the more global `Config.same_comment_per_PR_per_run_limit` if set.
	"""

	new_title: Optional[str]
	require: Optional[str | list[str]]
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

	status: Optional[str]

	target_branch: Optional[str]
	pr_branch: Optional[str]

	is_dry_run: Optional[bool]

	log_level: Optional[str]

	same_comment_per_PR_per_run_limit: int
	"""
	The maximum number of times the same comment can be posted on a pull request in one run of the script.
	Helps avoid rate limiting or throttling.
	Comments will be disambiguated by `Rule.comment_id` if set, otherwise, by `Rule.comment`.
	Default is 20.
	"""

	requeue_config: Optional[RequeueConfig]

	wait_after_review_s: Optional[int]

	reset_votes_after_changes: Optional[Collection[int]]

	rules: list[Rule]

	PAT: Optional[str]
	user_id: str

	is_stats_enabled: Optional[bool]