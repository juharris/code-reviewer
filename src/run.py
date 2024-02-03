import datetime
import hashlib
import logging
import os
import pathlib
import re
import sys
import time
import urllib.parse
from collections import Counter
from typing import Any, Collection, Optional

import requests
import yaml
from azure.devops.connection import Connection
from azure.devops.released.git import (Comment, CommentPosition,
                                       CommentThreadContext,
                                       GitBaseVersionDescriptor, GitClient,
                                       GitCommitDiffs, GitPullRequest,
                                       GitPullRequestCommentThread,
                                       GitPullRequestSearchCriteria,
                                       GitTargetVersionDescriptor, IdentityRef,
                                       IdentityRefWithVote,
                                       WebApiCreateTagRequestData)
from azure.devops.v7_1.policy import PolicyClient, PolicyEvaluationRecord
from azure.identity import ManagedIdentityCredential
from jsonpath import JSONPath
from msrest.authentication import BasicAuthentication, OAuthTokenAuthentication

from comment_search import CommentSearchResult, get_comment_id_marker
from config import Config, JsonPathCheck, PolicyEvaluationChecks
from file_diff import FileDiff
from voting import is_vote_allowed, map_int_vote, map_vote

# See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.0&tabs=HTTP for help with what's possible.

branch_pat = re.compile('^refs/heads/')

log_start = "*" * 100
attributes_with_patterns = ('description', 'merge_status', 'source_ref_name', 'target_ref_name', 'title')
pr_url_to_latest_commit_seen = {}

POLICY_DISPLAY_NAME_JSONPATH = JSONPath('$.configuration.settings.displayName')

# App ID of the Azure DevOps REST API itself (not of a specific org or project)
ADO_REST_API_AUTH_SCOPE = '499b84ac-1321-427f-aa17-267ca6975798/.default'


class Runner:
	config: Config
	config_hash: Optional[str] = None
	git_client: GitClient
	policy_client: PolicyClient
	rest_api_kwargs: dict[str, Any]

	def __init__(self, config_source: str) -> None:
		self.config_source = config_source
		self.logger = logging.getLogger(__name__)
		self.logger.setLevel(logging.INFO)
		f = logging.Formatter('%(asctime)s [%(levelname)s] - %(name)s:%(filename)s:%(funcName)s\n%(message)s')
		h = logging.StreamHandler()
		h.setFormatter(f)
		self.logger.addHandler(h)

	def run(self) -> None:
		# Log the docker image build timestamp for easier debugging.
		self.log_docker_image_build_timestamp()

		while True:
			try:
				self.load_config()
				self.review_prs()
			except:
				self.logger.exception(f"Error while trying to load the config or get pull requests to review.")

			wait_after_review_s = self.config.get('wait_after_review_s')
			if wait_after_review_s is not None:
				self.logger.debug("Waiting %s seconds before the next review.", wait_after_review_s)
				time.sleep(wait_after_review_s)
			else:
				break

	def log_docker_image_build_timestamp(self) -> None:
		docker_image_build_timestamp = None
		this_dir = os.path.dirname(__file__)
		timestamp_file_path = os.path.join(this_dir, '.docker_image_build_timestamp')
		if pathlib.Path(timestamp_file_path).exists():
			with open(timestamp_file_path, 'r') as f:
				docker_image_build_timestamp = f.read().strip()
		self.logger.info(f"Current time: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
				f" | Docker Image Build Date: {docker_image_build_timestamp}")

	def load_config(self) -> None:
		config_contents = None
		if self.config_source.startswith('https://') or self.config_source.startswith('http://'):
			max_num_tries = 3
			for try_num in range(max_num_tries):
				try:
					r = requests.get(self.config_source)
					r.raise_for_status()
					config_contents = r.text
					break
				except:
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

			log_level = logging.getLevelName(config.get('log_level', 'INFO'))
			self.logger.setLevel(log_level)

			unique_path_regexs = set()
			rules = config['rules']
			for rule in rules:
				for name in ('author',) + attributes_with_patterns:
					if pat := rule.get(f'{name}_pattern'):
						rule[f'{name}_regex'] = re.compile(pat, re.DOTALL) # type: ignore
				if (pat := rule.get('diff_pattern')) is not None:
					rule['diff_regex'] = re.compile(pat, re.DOTALL)
				if (pat := rule.get('path_pattern')) is not None:
					p = rule['path_regex'] = re.compile(pat)
					unique_path_regexs.add(p)

				vote = rule.get('vote')
				if isinstance(vote, str):
					rule['vote'] = map_vote(vote)

				if (rule_policy_checks := rule.get('policy_checks')) is not None:
					for rule_policy_check in rule_policy_checks:
						for evaluation_check in rule_policy_check['evaluation_checks']:
							evaluation_check['json_path_'] = JSONPath(evaluation_check['json_path'])
							if (pat := evaluation_check.get('pattern')) is not None:
								evaluation_check['regex'] = re.compile(pat)

				if (requeue := rule.get('requeue')) is not None:
					for check in requeue:
						check['json_path_'] = JSONPath(check['json_path'])
						if (pat := check.get('pattern')) is not None:
							check['regex'] = re.compile(pat)

			config['unique_path_regexs'] = unique_path_regexs

			self.config = config
			self.config_hash = config_hash
			pr_url_to_latest_commit_seen.clear()

			self.logger.info("Loaded configuration with %d rule(s).", len(rules))

	def _make_comment_stat_key(self, comment: Comment) -> tuple:
		author: IdentityRef = comment.author # type: ignore
		return (author.display_name, author.unique_name, comment.comment_type)

	def gather_comment_stats(self, threads: Collection[GitPullRequestCommentThread]) -> None:
		for thread in threads:
			comments: Collection[Comment] = thread.comments # type: ignore
			for comment in comments:
				if not comment.is_deleted:
					self.comment_stats[self._make_comment_stat_key(comment)] += 1
	
	def display_stats(self) -> None:
		if self.logger.isEnabledFor(logging.INFO) and len(self.comment_stats) > 0:
			s = f"{log_start}\nComment stats:\nCount | Author & Comment Type\n"
			num_top_commenters_to_show = self.config.get('num_top_commenters_to_show', 12)
			for (name, unique_name, comment_type), count in self.comment_stats.most_common(num_top_commenters_to_show):
				s += f"  {count: 5d} | {name} ({unique_name}) ({comment_type})\n"
			s += log_start
			self.logger.info(s)

	def review_prs(self):
		personal_access_token = self.config.get('PAT')
		if not personal_access_token:
			personal_access_token = os.environ.get('CR_ADO_PAT')
			self.config['PAT'] = personal_access_token

		if personal_access_token:
			credentials = BasicAuthentication('', personal_access_token)
			self.rest_api_kwargs = {'auth': ('', personal_access_token)}

		else:
			managed_identity_client_id = os.environ.get('CR_MANAGED_IDENTITY_CLIENT_ID')
			if managed_identity_client_id:
				managed_identity_credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
				token = managed_identity_credential.get_token(ADO_REST_API_AUTH_SCOPE)
				token_dict = {'access_token': token.token}
				credentials = OAuthTokenAuthentication(managed_identity_client_id, token_dict)
				self.rest_api_kwargs = {'headers': {"Authorization": f"Bearer {token.token}"}}

			else:
				raise ValueError("No personal access token and no managed identity client ID provided. Please set one of the environment variables CR_ADO_PAT or CR_MANAGED_IDENTITY_CLIENT_ID or set 'PAT' in the config file.")

		organization_url = self.config['organization_url']
		project = self.config['project']
		repository_name = self.config['repository_name']
		connection = Connection(base_url=organization_url, creds=credentials)
		self.git_client = connection.clients.get_git_client()
		self.policy_client = connection.clients_v7_1.get_policy_client()
		# TODO Try to get the current user's email and ID, but getting auth issues:
		# Try to get the client says "The requested resource requires user authentication: https://app.vssps.visualstudio.com/_apis".
		# from azure.devops.released.profile.profile_client import ProfileClient
		# profile_client: ProfileClient = connection.clients.get_profile_client()
		# r = profile_client.get_profile('me')

		status = self.config.get('status', 'active')
		top = self.config.get('top', 50)
		pr_branch = self.config.get('pr_branch')
		target_branch = self.config.get('target_branch')
		source_ref = f'refs/heads/{urllib.parse.quote(pr_branch)}' if pr_branch else None
		target_ref = f'refs/heads/{urllib.parse.quote(target_branch)}' if target_branch else None
		search = GitPullRequestSearchCriteria(repository_id=repository_name, status=status, source_ref_name=source_ref, target_ref_name=target_ref)
		prs: Collection[GitPullRequest] = self.git_client.get_pull_requests(repository_name, search, project, top=top)
		self.logger.debug("Found %d pull request(s).", len(prs))
		self.comment_stats = Counter()
		for pr in prs:
			pr_url = f"{organization_url}/{urllib.parse.quote(project)}/_git/{urllib.parse.quote(repository_name)}/pullrequest/{pr.pull_request_id}"
			try:
				self.review_pr(pr, pr_url)

				# Only acknowledge reviewing after successfully going through all rules.
				# This could help to get around rate limiting.
				pr_url_to_latest_commit_seen[pr_url] = pr.last_merge_source_commit
			except:
				self.logger.exception(f"Error while reviewing pull request called \"{pr.title}\" at {pr_url}")

		if self.config.get('is_stats_enabled'):
			self.display_stats()


	def review_pr(self, pr: GitPullRequest, pr_url: str):
		project = self.config['project']
		repository_id = pr.repository.id # type: ignore
		rules = self.config['rules']

		user_id = self.config['user_id']
		is_dry_run = self.config.get('is_dry_run', False)

		pr_author: IdentityRef = pr.created_by # type: ignore
		reviewers: list[IdentityRefWithVote] = pr.reviewers # type: ignore
		self.logger.debug(f"%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

		current_vote: Optional[int] = None
		reviewer: Optional[IdentityRefWithVote] = None
		for r in reviewers:
			if r.id == user_id:
				reviewer = r
				current_vote = r.vote
				break

		if reviewer is None:
			reviewer = IdentityRefWithVote(id=user_id)

		threads: Optional[list[GitPullRequestCommentThread]] = None

		if self.config.get('is_stats_enabled'):
			threads = self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
			assert threads is not None
			self.gather_comment_stats(threads)

		# TODO Make comments to delete configurable and support patterns.
		# delete_comment = "Automated comment: Please add a space after `//`."
		# threads = self.delete_comments(pr, pr_url, project, repository_id, delete_comment)

		if pr.status == 'completed':
			# Don't comment on pull requests that are completed because the diff cannot be computed.
			# Probably can't vote either.
			return
		
		policy_evaluations: Optional[list[dict]] = None
		file_diffs = self.get_diffs(pr, pr_url)

		for rule in rules:
			# All checks must match.
			if (author_regex := rule.get('author_regex')) is not None:
				if not author_regex.match(pr_author.display_name) and not author_regex.match(pr_author.unique_name):
					continue

			match_found = True
			for name in attributes_with_patterns:
				if (regex := rule.get(f'{name}_regex')) is not None:
					val = getattr(pr, name)
					if val is not None and not regex.match(val):
						match_found = False
						break

			if rule.get('is_imperative_title_enforced'):
				if self.is_imperative(str(pr.title)):
					match_found = False

			is_draft_req = rule.get('is_draft')
			if is_draft_req is not None and is_draft_req != pr.is_draft:
				match_found = False

			if not match_found:
				continue

			# Check policy evaluations before checking files because there are often issues when checking files.
			rule_policy_checks = rule.get('policy_checks')
			if rule_policy_checks is not None:
				match_found, policy_evaluations = self.check_policies(pr, pr_url, policy_evaluations, rule_policy_checks)

				if not match_found:
					continue

			comment = rule.get('comment')
			comment_id = rule.get('comment_id')
			path_regex = rule.get('path_regex')
			diff_regex = rule.get('diff_regex')
			if path_regex is not None:
				match_found = False
				for file_diff in file_diffs:
					if not path_regex.match(file_diff.path):
						continue
					if diff_regex is None:
						# We don't need to check the diff.
						match_found = True
						break
					else:
						if file_diff.diff is not None:
							# Handle edit.
							for block in file_diff.diff['blocks']:
								change_type = block['changeType']
								if change_type == 0 or change_type == 2:
									continue
								assert change_type == 1 or change_type == 3, f"Unexpected change type: {change_type}"
								for line_num, line in enumerate(block['mLines'], start=block['mLine']):
									local_match_found, threads = self.handle_diff_check(pr, pr_url, project,  is_dry_run, pr_author, threads, comment, comment_id, diff_regex, file_diff, line_num, line)
									match_found = match_found or local_match_found
						if file_diff.contents is not None:
							# Handle add.
							lines = file_diff.contents.splitlines()
							for line_num, line in enumerate(lines, 1):
								local_match_found, threads = self.handle_diff_check(pr, pr_url, project,  is_dry_run, pr_author, threads, comment, comment_id, diff_regex, file_diff, line_num, line)
								match_found = match_found or local_match_found

			if not match_found:
				continue

			self.logger.debug("Rule matches: %s", rule)

			optional_reviewers = rule.get('add_optional_reviewers')
			required_reviewers = rule.get('require')
			tags = rule.get('add_tags')
			new_title = rule.get('new_title')
			requeue = rule.get('requeue')

			if tags is not None:
				self.add_tags(pr, pr_url, project, is_dry_run, tags)

			# Don't comment on the PR overview for an issue with a diff.
			if comment is not None and diff_regex is None:
				threads = threads or self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
				existing_comment_info = self.find_comment(threads, comment, comment_id)
				if existing_comment_info is None:
					self.send_comment(pr, pr_url, is_dry_run, pr_author, comment, threads, comment_id=comment_id)
				else:
					self.update_comment(pr, pr_url, is_dry_run, pr_author, comment, comment_id, existing_comment_info)

			if optional_reviewers is not None:
				self.add_optional_reviewers(pr, pr_url, project, pr_author, is_dry_run, reviewers, optional_reviewers)

			if required_reviewers is not None:
				self.add_required_reviewers(pr, pr_url, project, pr_author, is_dry_run, reviewers, required_reviewers)

			if new_title is not None:
				self.set_new_title(pr, pr_url, project, is_dry_run, new_title)

			if requeue is not None:
				if policy_evaluations is None:
					project_id = pr.repository.project.id # type: ignore
					policy_evaluations_: list[PolicyEvaluationRecord] = self.policy_client.get_policy_evaluations(project, f'vstfs:///CodeReview/CodeReviewId/{project_id}/{pr.pull_request_id}')
					policy_evaluations = [c.as_dict() for c in policy_evaluations_]
				requeue_comment = rule.get('requeue_comment')
				if requeue_comment is not None:
					threads = threads or self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
				self.requeue_policy(pr, pr_url, project, is_dry_run, policy_evaluations, threads, requeue, requeue_comment)

			vote = rule.get('vote')
			# Votes were converted when the config was loaded.
			assert vote is None or isinstance(vote, int), f"Vote must be an integer. Got: {vote} with type: {type(vote)}"
			# Can't vote on a draft.
			if not pr.is_draft and is_vote_allowed(current_vote, vote):
				assert vote is not None
				reviewer.vote = current_vote = vote
				vote_str = map_int_vote(vote)
				if not is_dry_run:
					self.logger.info("SETTING VOTE: '%s'\nTitle: \"%s\"\nBy %s (%s)\n%s", vote_str, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
					self.git_client.create_pull_request_reviewer(reviewer, repository_id, pr.pull_request_id, reviewer_id=user_id, project=project)
				else:
					self.logger.info("Would vote: '%s'\nTitle: \"%s\"\nBy %s (%s)\n%s", vote_str, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

	def add_optional_reviewers(self, pr: GitPullRequest, pr_url: str, project: str, pr_author: IdentityRef, is_dry_run: bool, reviewers: list[IdentityRefWithVote], optional_reviewers: Collection[str]):
		for optional_reviewer in optional_reviewers:
			is_already_optional = False
			for req in reviewers:
				if req.id == optional_reviewer:
					is_already_optional = not req.has_declined
					break
			else:
				req = IdentityRefWithVote(id=optional_reviewer)
				reviewers.append(req)
			if not is_already_optional:
				if not is_dry_run:
					self.logger.info("ADDING OPTIONAL REVIEWER: %s\nTitle: \"%s\"\nBy %s (%s)\n%s", optional_reviewer, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
					repository_id = pr.repository.id # type: ignore
					self.git_client.create_pull_request_reviewer(req, repository_id, pr.pull_request_id, reviewer_id=optional_reviewer, project=project)
				else:
					self.logger.info("Would add optional reviewer: %s\nTitle: \"%s\"\nBy %s (%s)\n%s", optional_reviewer, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

	def add_required_reviewers(self, pr: GitPullRequest, pr_url: str, project: str, pr_author: IdentityRef, is_dry_run: bool, reviewers: list[IdentityRefWithVote], required_reviewers: str | Collection[str]):
		if isinstance(required_reviewers, str):
			required_reviewers = (required_reviewers, )

		for required_reviewer in required_reviewers:
			is_already_required = False
			for req in reviewers:
				if req.id == required_reviewer:
					is_already_required = req.is_required
					req.is_required = True
					break
			else:
				req = IdentityRefWithVote(is_required=True, id=required_reviewer)
				reviewers.append(req)
			if not is_already_required:
				if not is_dry_run:
					self.logger.info("REQUIRING: %s\nTitle: \"%s\"\nBy %s (%s)\n%s", required_reviewer, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
					repository_id = pr.repository.id # type: ignore
					self.git_client.create_pull_request_reviewer(req, repository_id, pr.pull_request_id, reviewer_id=required_reviewer, project=project)
				else:
					self.logger.info("Would require: %s\nTitle: \"%s\"\nBy %s (%s)\n%s", required_reviewer, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

	def add_tags(self, pr: GitPullRequest, pr_url: str, project: str, is_dry_run: bool, tags: list[str]):
		for tag in tags:
			normalized_tag = tag.casefold()
			if pr.labels is None or not any(label.name.casefold() == normalized_tag for label in pr.labels):
				if not is_dry_run:
					repository_id = pr.repository.id # type: ignore
					label = WebApiCreateTagRequestData(tag)
					self.logger.info("ADDING TAG: \"%s\"\nTitle: \"%s\"\n%s", tag, pr.title, pr_url)
					self.git_client.create_pull_request_label(label, repository_id, pr.pull_request_id, project=project)
				else:
					self.logger.info("Would add tag: \"%s\"\nTitle: \"%s\"\n%s", tag, pr.title, pr_url)

	def check_policies(self, pr: GitPullRequest, pr_url: str, policy_evaluations: Optional[list[dict]], rule_policy_checks: list[PolicyEvaluationChecks]) -> tuple[bool, list[dict]]:
		project_id = pr.repository.project.id # type: ignore
		project = self.config['project']
		if policy_evaluations is None:
			policy_evaluations_: list[PolicyEvaluationRecord] = self.policy_client.get_policy_evaluations(project, f'vstfs:///CodeReview/CodeReviewId/{project_id}/{pr.pull_request_id}')
			policy_evaluations = [c.as_dict() for c in policy_evaluations_]
			self.logger.debug("Policy evaluations: %s\nfor %s", policy_evaluations, pr_url)
		all_rules_match = all(self.is_rule_match_policy_evals(r, policy_evaluations) for r in rule_policy_checks)
		return all_rules_match, policy_evaluations

	def is_rule_match_policy_evals(self, rule_policy_check: PolicyEvaluationChecks, policy_evaluations: list[dict]) -> bool:
		"""
		:returns: `True` if any of the policy evaluations match the rule.
		"""
		result = any(self.is_policy_rule_match(rule_policy_check, policy_evaluation) for policy_evaluation in policy_evaluations)
		self.logger.debug("Policy check %s found match: %s", rule_policy_check, result)
		return result

	def is_policy_rule_match(self, rule_policy_check: PolicyEvaluationChecks, policy_evaluation: dict) -> bool:
		"""
		:returns: `True` if the policy evaluation matches the rule.
		"""
		return all(self.is_check_match(check, policy_evaluation) for check in rule_policy_check['evaluation_checks'])

	def is_check_match(self, check: JsonPathCheck, data: dict) -> bool:
		"""
		:returns: `True` if the check matches the data.
		"""
		matches = check['json_path_'].search(data)
		if matches is None or len(matches) == 0:
			return False
		self.logger.debug("JSON Path '%s' matches: %s", check['json_path'], matches)
		if (pat := check.get('regex')) is not None:
			# `None` can be in matches maybe when a value such as a status is not set?
			return any(m is not None and pat.match(m) for m in matches)
		return True

	def handle_diff_check(self, pr: GitPullRequest, pr_url: str, project: str, is_dry_run: bool, pr_author, threads: Optional[list[GitPullRequestCommentThread]], comment: Optional[str], comment_id: Optional[str], diff_regex: re.Pattern, file_diff: FileDiff, line_num: int, line: str):
		match_found = False
		if (m := diff_regex.match(line)):
			repository_id = pr.repository.id # type: ignore
			match_found = True
			self.logger.debug("Matched diff regex: %s for line \"%s\"\nURL: %s", diff_regex.pattern, line, pr_url)
			if comment is not None:
				threads = threads or self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
				existing_comment_info = self.find_comment(threads, comment, comment_id, file_diff.path, line_num)
				if existing_comment_info is None:
					# Docs say the character indices are 0-based, but they seem to be 1-based.
					# When 0 is given, the context of the line is hidden in the Overview.
					thread_context = CommentThreadContext(file_diff.path, 
						right_file_start=CommentPosition(line_num, m.pos + 1),
						right_file_end=CommentPosition(line_num, m.endpos + 1))
					self.send_comment(pr, pr_url, is_dry_run, pr_author, comment, threads, thread_context, comment_id=comment_id)
				else:
					self.update_comment(pr, pr_url, is_dry_run, pr_author, comment, comment_id, existing_comment_info)
		return match_found, threads

	def get_diffs(self, pr: GitPullRequest, pr_url: str) -> list[FileDiff]:
		result = []
		latest_commit = pr.last_merge_source_commit
		if latest_commit == pr_url_to_latest_commit_seen.get(pr_url):
			self.logger.debug("Skipping checking diff for commit already seen (%s).", latest_commit)
			return result

		# Get the files changed.
		pr_branch = branch_pat.sub('', pr.source_ref_name) # type: ignore
		pr_branch = urllib.parse.quote(pr_branch)
		target = GitTargetVersionDescriptor(target_version=pr_branch, target_version_type='branch')
		# The branch to merge into.
		base_branch = branch_pat.sub('', pr.target_ref_name) # type: ignore
		base_branch = urllib.parse.quote(base_branch)
		base = GitBaseVersionDescriptor(base_version=base_branch, base_version_type='branch')

		organization_url = self.config['organization_url']
		project = self.config['project']
		repository_id = pr.repository.id # type: ignore

		diffs: GitCommitDiffs = self.git_client.get_commit_diffs(repository_id, project, diff_common_commit=True, base_version_descriptor=base, target_version_descriptor=target, top=100000)
		changes: list[dict] = diffs.changes # type: ignore

		path_regexs = self.config['unique_path_regexs']

		for change in changes:
			item = change['item']
			change_type = change['changeType']
			# TODO Make sure all change types are handled.
			# TODO Figure out how to get diff for 'edit, rename'.
			# The result for the URL was not found.
			if not item.get('isFolder'):
				original_path = item['path']
				modified_path = change.get('sourceServerItem', original_path)
				if not any(regex.match(modified_path) for regex in path_regexs):
					continue

				try:
					if change_type == 'edit' or change_type == 'edit, rename':
						if change_type == 'edit, rename':
							original_path = change['sourceServerItem']
							modified_path = item['path']
						self.logger.debug("Getting diff for \"%s\".", modified_path)
						# Use an undocumented API to get the diff.
						# Found at https://stackoverflow.com/questions/41713616
						diff_url =f'{organization_url}/{project}/_api/_versioncontrol/fileDiff?__v=5&diffParameters={{"originalPath":"{original_path}","originalVersion":"{diffs.base_commit}","modifiedPath":"{modified_path}","modifiedVersion":"{diffs.target_commit}","partialDiff":true,"includeCharDiffs":false}}&repositoryId={repository_id}'
						diff_request = requests.get(diff_url, **self.rest_api_kwargs)
						diff_request.raise_for_status()
						diff = diff_request.json()
						result.append(FileDiff(change_type, modified_path, original_path=original_path, diff=diff))
					elif change_type == 'add':
						self.logger.debug("Getting new file \"%s\".", modified_path)
						url = item['url']
						request = requests.get(url, **self.rest_api_kwargs)
						request.raise_for_status()
						contents = request.text
						result.append(FileDiff(change_type, modified_path, contents=contents))
					else:
						self.logger.debug("Skipping diff for \"%s\" for \"%s\".", change_type, modified_path)
				except:
					self.logger.exception("Failed to get diff for \"%s\" for \"%s\".\n  Title: \"%s\"\n  URL: %s", change_type, modified_path, pr.title, pr_url)

		return result

	def find_comment(self, threads: list[GitPullRequestCommentThread], comment: str, comment_id: Optional[str] = None, path: Optional[str] = None, line_num: Optional[int] = None) -> Optional[CommentSearchResult]:
		result = None
		current_user_id = self.config['user_id']
		comment_id_marker = get_comment_id_marker(comment_id)
		assert threads is not None
		for thread in threads:
			comments: Collection[Comment] = thread.comments # type: ignore
			# We could filter by `thread.status` (can be 'active', 'unknown', ...), but we want to find resolved threads too and reactivate them, if necessary.
			if path is not None:
				assert line_num is not None
				if thread.thread_context is None:
					continue
				if thread.thread_context.file_path != path:
					# Not the path we're looking for.
					continue
				# Same path.
				if thread.thread_context.right_file_start is None:
					continue
				if thread.thread_context.right_file_start.line != line_num:
					continue
			for c in comments:
				if not c.is_deleted:
					# Prefer finding a comment by ID and ignoring the core content because it should be simpler.
					content: Optional[str] = c.content
					if comment_id is not None and content is not None:
						author: Optional[IdentityRef] = c.author
						if author is not None and author.id == current_user_id and content.endswith(comment_id_marker):
							return CommentSearchResult(c, thread)

					# Even if `comment_id` is set, we still want to try to find a comment with the same core content.
					# This can happen if an old comment now has an ID and we should update old versions of the comment to include the ID.
					if content == comment:
						return CommentSearchResult(c, thread)
		return result

	def is_imperative(self, pr_title: str) -> bool:
		# Remove tags from the beginning of the title.
		tag_start = pr_title.find('[')
		if tag_start != -1:
			tag_end = pr_title.rfind(']')
			if tag_end != -1:
				pr_title = pr_title[tag_end + 1:].strip()

		# Check if the title starts with an imperative verb.
		first_space_index = pr_title.find(' ')
		if first_space_index == -1:
			first_word = pr_title
		else:
			first_word = pr_title[:first_space_index]

		# Just use some simple checks for now.
		for ending in ("ed", "ing", "ion"):
			if first_word.endswith(ending):
				return False

		return True

	def send_comment(self, pr: GitPullRequest, pr_url: str, is_dry_run: bool, pr_author: IdentityRef, comment: str, threads: list[GitPullRequestCommentThread], thread_context: Optional[CommentThreadContext]=None, status='active', comment_id: Optional[str] = None):
		if comment_id is not None:
			comment += get_comment_id_marker(comment_id)
		comment_ = Comment(content=comment)
		thread = GitPullRequestCommentThread(comments=[comment_], status=status, thread_context=thread_context)
		if not is_dry_run:
			self.logger.info("COMMENTING: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
			project = self.config['project']
			repository_id = pr.repository.id # type: ignore
			self.git_client.create_thread(thread, repository_id, pr.pull_request_id, project=project)
		else:
			self.logger.info("Would comment: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

		threads.append(thread)

	def update_comment(self, pr: GitPullRequest, pr_url: str, is_dry_run: bool, pr_author: IdentityRef, comment: str, comment_id: Optional[str], existing_comment_info: CommentSearchResult, status='active'):
		thread: GitPullRequestCommentThread = existing_comment_info.thread
		existing_comment: Comment = existing_comment_info.comment

		if thread.status != status:
			thread.status = status
			if not is_dry_run:
				self.logger.info("CHANGING THREAD STATUS: \"%s\" for comment: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", status, comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
				project = self.config['project']
				repository_id = pr.repository.id # type: ignore
				thread_ = GitPullRequestCommentThread(status=status)
				self.git_client.update_thread(thread_, repository_id, pr.pull_request_id, thread.id, project=project)
			else:
				self.logger.info("Would update thread status: \"%s\" for comment: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", status, comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

		if comment_id is not None:
			comment += get_comment_id_marker(comment_id)
		if existing_comment.content != comment:
			existing_comment.content = comment
			if not is_dry_run:
				self.logger.info("UPDATING COMMENT: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
				project = self.config['project']
				repository_id = pr.repository.id # type: ignore
				comment_ = Comment(content=comment)
				self.git_client.update_comment(comment_, repository_id, pr.pull_request_id, thread.id, existing_comment.id, project=project)
			else:
				self.logger.info("Would update comment: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)


	def delete_comments(self, pr, pr_url: str, project, repository_id, delete_comment: Optional[str]) -> Optional[list[GitPullRequestCommentThread]]:
		if not delete_comment:
			return None

		is_dry_run = self.config.get('is_dry_run', False)
		threads: list[GitPullRequestCommentThread] = self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
		pr_author: IdentityRef = pr.created_by # type: ignore
		for thread in threads:
			comments: Collection[Comment] = thread.comments # type: ignore
			for c in comments:
				if c.content == delete_comment:
					if not is_dry_run:
						self.logger.info("DELETING COMMENT: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", c.content, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
						self.git_client.delete_comment(repository_id, pr.pull_request_id, thread.id, c.id, project=project)
					else:
						self.logger.info("Would delete comment: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", c.content, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
		return threads

	def set_new_title(self, pr: GitPullRequest, pr_url: str, project: str, is_dry_run: bool, new_title: str):
		new_title = new_title.format(TITLE=pr.title)
		if not is_dry_run:
			repository_id = pr.repository.id # type: ignore
			self.logger.info("SETTING TITLE TO: \"%s\" from \"%s\"\n%s", new_title, pr.title, pr_url)
			self.git_client.update_pull_request(GitPullRequest(title=new_title), repository_id, pr.pull_request_id, project=project)
		else:
			self.logger.info("Would set title to: \"%s\" from \"%s\"\n%s", new_title, pr.title, pr_url)
		pr.title = new_title

	def requeue_policy(self, pr: GitPullRequest, pr_url: str, project: str, is_dry_run: bool, policy_evaluations: list[dict], threads: Optional[list[GitPullRequestCommentThread]], requeue: list[JsonPathCheck], requeue_comment: Optional[str]):
		# Find the policy to requeue.
		for policy_evaluation in policy_evaluations:
			if all(self.is_check_match(rule_policy_check, policy_evaluation) for rule_policy_check in requeue):
				name_matches = POLICY_DISPLAY_NAME_JSONPATH.search(policy_evaluation)
				name = name_matches[0] if (name_matches is not None and len(name_matches) > 0) else None
				evaluation_id = policy_evaluation.get('evaluation_id')
				if evaluation_id is None:
					self.logger.warning("Cannot requeue check for \"%s\" because no evaluation ID was found for policy evaluation: %s", name, policy_evaluation)
					break
				if not is_dry_run:
					self.logger.info("REQUEUING \"%s\" (%s) for \"%s\"\n%s", name, evaluation_id, pr.title, pr_url)
					self.policy_client.requeue_policy_evaluation(project, evaluation_id)
				else:
					self.logger.info("Would requeue \"%s\" (%s) for \"%s\"\n%s", name, evaluation_id, pr.title, pr_url)

				if requeue_comment is not None:
					assert threads is not None, "`threads` must be provided to add a comment."
					pr_author: IdentityRef = pr.created_by # type: ignore
					self.send_comment(pr, pr_url, is_dry_run, pr_author, requeue_comment, threads, status='closed')


def main():
	config_source = sys.argv[1]
	runner = Runner(config_source)
	runner.run()


if __name__ == '__main__':
	main()
