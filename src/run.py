import hashlib
import logging
import os
import re
import sys
import time
from typing import Collection, Optional

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
                                       IdentityRefWithVote)
from msrest.authentication import BasicAuthentication

from config import Config, Rule
from file_diff import FileDiff

# See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.0&tabs=HTTP for help with what's possible.

branch_pat = re.compile('^refs/heads/')

log_start = "*" * 100
attributes_with_patterns = ('description', 'title')
pr_url_to_latest_commit_seen = {}

class Runner:
	config: Config
	config_hash: Optional[str] = None

	def __init__(self, config_path: str) -> None:
		self.config_path = config_path
		self.logger = logging.getLogger(__name__)
		self.logger.setLevel(logging.INFO)
		f = logging.Formatter('%(asctime)s [%(levelname)s] - %(name)s:%(filename)s:%(funcName)s\n%(message)s')
		h = logging.StreamHandler()
		h.setFormatter(f)
		self.logger.addHandler(h)

	def run(self):
		while True:
			self.load_config()
			self.review_prs()

			wait_after_review_s = self.config.get('wait_after_review_s')
			if wait_after_review_s is not None:
				self.logger.debug("Waiting %s seconds before the next review.", wait_after_review_s)
				time.sleep(wait_after_review_s)
			else:
				break

	def load_config(self):
		with open(self.config_path, 'r') as f:
			config_contents = f.read()
			config_hash = hashlib.sha256(config_contents.encode('utf-8')).hexdigest()
		if config_hash != self.config_hash:
			print(f"Loading configuration from '{self.config_path}'.")
			config: Config = yaml.safe_load(config_contents)

			log_level = logging.getLevelName(config.get('log_level', 'INFO'))
			self.logger.setLevel(log_level)

			for rule in config['rules']:
				for name in ('author',) + attributes_with_patterns:
					if pat := rule.get(f'{name}_pattern'):
						rule[f'{name}_regex'] = re.compile(pat, re.DOTALL | re.IGNORECASE) # type: ignore
				if pat := rule.get('diff_pattern'):
					rule['diff_regex'] = re.compile(pat, re.DOTALL)
				if pat := rule.get('path_pattern'):
					rule['path_regex'] = re.compile(pat)
			self.config = config
			self.config_hash = config_hash
			pr_url_to_latest_commit_seen.clear()

	def review_prs(self):
		personal_access_token = self.config.get('PAT')
		if not personal_access_token:
			personal_access_token = os.environ.get('CR_ADO_PAT')
			self.config['PAT'] = personal_access_token

		if not personal_access_token:
			raise ValueError("No personal access token provided. Please set the CR_ADO_PAT environment variable or add set 'PAT' the config file.")

		credentials = BasicAuthentication('', personal_access_token)

		organization_url = self.config['organization_url']
		project = self.config['project']
		repository_name = self.config['repository_name']
		connection = Connection(base_url=organization_url, creds=credentials)
		self.git_client: GitClient = connection.clients.get_git_client()
		# TODO Try to get the current user's email and ID, but getting auth issues:
		# Try to get the client says "The requested resource requires user authentication: https://app.vssps.visualstudio.com/_apis".
		# from azure.devops.released.profile.profile_client import ProfileClient
		# profile_client: ProfileClient = connection.clients.get_profile_client()
		# r = profile_client.get_profile('me')

		status = self.config.get('status', 'Active')
		top = self.config.get('top', 50)
		pr_branch = self.config.get('pr_branch')
		source_ref = f'refs/heads/{pr_branch}' if pr_branch else None
		search = GitPullRequestSearchCriteria(repository_id=repository_name, status=status, source_ref_name=source_ref)
		prs: Collection[GitPullRequest] = self.git_client.get_pull_requests(repository_name, search, project, top=top)
		for pr in prs:
			pr_url = f"{organization_url}/{project}/_git/{repository_name}/pullrequest/{pr.pull_request_id}"
			try:
				self.review_pr(pr, pr_url)
			except:
				self.logger.exception(f"Error while reviewing pull request called \"{pr.title}\" at {pr_url}")


	def review_pr(self, pr: GitPullRequest, pr_url: str):
		project = self.config['project']
		repository_id = pr.repository.id # type: ignore
		rules = self.config['rules']

		current_user = self.config['current_user']
		user_id = self.config['user_id']
		is_dry_run = self.config.get('is_dry_run', False)

		pr_author: IdentityRef = pr.created_by # type: ignore
		reviewers: list[IdentityRefWithVote] = pr.reviewers # type: ignore
		self.logger.debug(f"%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

		file_diffs = self.get_diffs(pr, pr_url, rules)

		current_vote: Optional[int] = None
		reviewer: Optional[IdentityRefWithVote] = None
		for reviewer in reviewers:
			if reviewer.unique_name == current_user:
				current_vote = reviewer.vote
				break

		threads: Optional[list[GitPullRequestCommentThread]] = None

		# TODO Make comments to delete configurable and support patterns.
		# delete_comment = "Automated comment: Please add a space after `//`."
		# threads = self.delete_comments(pr, pr_url, project, repository_id, delete_comment)

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

			if not match_found:
				continue

			comment = rule.get('comment')
			require_id = rule.get('require')
			diff_regex = rule.get('diff_regex')
			if diff_regex is not None or require_id is not None:
				path_regex = rule.get('path_regex')
				match_found = False
				for file_diff in file_diffs:
					if path_regex is not None and not path_regex.match(file_diff.path):
						continue
					if diff_regex is None and require_id is not None:
						# There is a required reviewer, but we don't need to check the diff.
						match_found = True
						break
					if diff_regex is not None:
						if file_diff.diff is not None:
							# Handle edit.
							for block in file_diff.diff['blocks']:
								change_type = block['changeType']
								if change_type == 0 or change_type == 2:
									continue
								assert change_type == 1 or change_type == 3, f"Unexpected change type: {change_type}"
								for line_num, line in enumerate(block['mLines'], start=block['mLine']):
									local_match_found, threads = self.handle_diff_check(pr, pr_url, project,  is_dry_run, pr_author, threads, comment, diff_regex, file_diff, line_num, line)
									match_found = match_found or local_match_found
						if file_diff.contents is not None:
							# Handle add.
							lines = file_diff.contents.splitlines()
							for line_num, line in enumerate(lines, 1):
								local_match_found, threads = self.handle_diff_check(pr, pr_url, project,  is_dry_run, pr_author, threads, comment, diff_regex, file_diff, line_num, line)
								match_found = match_found or local_match_found
			
			if not match_found:
				continue

			self.logger.debug("Rule matches: %s", rule)

			# Don't comment on the PR overview for an issue with a diff.
			if comment is not None and diff_regex is None:
				# Check to see if it's already commented in an active thread.
				# Eventually we could try to find the thread with the comment and reactivate the thread, and/or reply again.
				threads = threads or self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
				if not self.does_comment_exist(threads, comment):
					self.send_comment(pr, pr_url, is_dry_run, pr_author, comment, threads)

			if require_id is not None:
				is_already_required = False
				for req in reviewers:
					if req.unique_name == current_user:
						is_already_required = req.is_required
						req.is_required = True
						break
				else:
					req = IdentityRefWithVote(is_required=True, id=require_id)
					reviewers.append(req)
				if not is_already_required:
					if not is_dry_run:
						self.logger.info("REQUIRING: %s\nTitle: \"%s\"\nBy %s (%s)\n%s", require_id, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
						self.git_client.create_pull_request_reviewer(req, repository_id, pr.pull_request_id, reviewer_id=user_id, project=project)
					else:
						self.logger.info("Would require: %s\nTitle: \"%s\"\nBy %s (%s)\n%s", require_id, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

			# Can't vote on a draft.
			# Only vote if the new vote is more rejective (more negative) than the current vote.
			vote: Optional[int] = rule.get('vote')
			if not pr.is_draft and vote is not None and (current_vote is None or vote < current_vote):
				if reviewer is None:
					reviewer = IdentityRefWithVote(id=user_id)
					reviewers.append(reviewer)
				reviewer.vote = current_vote = vote
				if not is_dry_run:
					self.logger.info("SETTING VOTE: %d\nTitle: \"%s\"\nBy %s (%s)\n%s", vote, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
					self.git_client.create_pull_request_reviewer(reviewer, repository_id, pr.pull_request_id, reviewer_id=user_id, project=project)
				else:
					self.logger.info("Would set vote: %d\nTitle: \"%s\"\nBy %s (%s)\n%s", vote, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

	def handle_diff_check(self, pr: GitPullRequest, pr_url: str, project: str, is_dry_run: bool, pr_author, threads: Optional[list[GitPullRequestCommentThread]], comment: Optional[str], diff_regex: re.Pattern, file_diff: FileDiff, line_num: int, line: str):
		match_found = False
		if (m := diff_regex.match(line)):
			repository_id = pr.repository.id # type: ignore
			match_found = True
			self.logger.debug("Matched diff regex: %s for line \"%s\"\nURL: %s", diff_regex.pattern, line, pr_url)
			if comment is not None:
				threads = threads or self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
				if not self.does_comment_exist(threads, comment, file_diff.path, line_num):
					# Docs say the character indices are 0-based, but they seem to be 1-based.
					# When 0 is given, the context of the line is hidden in the Overview.
					thread_context = CommentThreadContext(file_diff.path, 
						right_file_start=CommentPosition(line_num, m.pos + 1),
						right_file_end=CommentPosition(line_num, m.endpos + 1))
					self.send_comment(pr, pr_url, is_dry_run, pr_author, comment, threads, thread_context)
		return match_found, threads

	def get_diffs(self, pr: GitPullRequest, pr_url: str, rules: list[Rule]) -> list[FileDiff]:
		result = []
		latest_commit = pr.last_merge_source_commit
		if latest_commit == pr_url_to_latest_commit_seen.get(pr_url):
			self.logger.debug("Skipping checking diff for commit already seen (%s).", latest_commit)
			return result

		# Get the files changed.
		pr_url_to_latest_commit_seen[pr_url] = latest_commit
		pr_branch = branch_pat.sub('', pr.source_ref_name) # type: ignore
		target = GitTargetVersionDescriptor(target_version=pr_branch, target_version_type='branch')
		# The branch to merge into.
		base_branch = branch_pat.sub('', pr.target_ref_name) # type: ignore
		base = GitBaseVersionDescriptor(base_version=base_branch, base_version_type='branch')

		organization_url = self.config['organization_url']
		project = self.config['project']
		repository_id = pr.repository.id # type: ignore
		personal_access_token: str = self.config['PAT'] # type: ignore

		diffs: GitCommitDiffs = self.git_client.get_commit_diffs(repository_id, project, diff_common_commit=True, base_version_descriptor=base, target_version_descriptor=target)
		changes: list[dict] = diffs.changes # type: ignore

		path_regexs = tuple(r for r in (rule.get('path_regex') for rule in rules) if r is not None)

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
						diff_request = requests.get(diff_url, auth=('', personal_access_token))
						diff_request.raise_for_status()
						diff = diff_request.json()
						result.append(FileDiff(change_type, modified_path, original_path=original_path, diff=diff))
					elif change_type == 'add':
						self.logger.debug("Getting new file \"%s\".", modified_path)
						url = item['url']
						request = requests.get(url, auth=('', personal_access_token))
						request.raise_for_status()
						contents = request.text
						result.append(FileDiff(change_type, modified_path, contents=contents))
					else:
						self.logger.debug("Skipping diff for \"%s\" for \"%s\".", change_type, modified_path)
				except:
					self.logger.exception("Failed to get diff for \"%s\" for \"%s\".", change_type, modified_path)
		return result

	def does_comment_exist(self, threads: list[GitPullRequestCommentThread], comment: str, path: Optional[str] = None, line_num: Optional[int] = None) -> bool:
		result = False
		assert threads is not None
		for thread in threads:
			comments: Collection[Comment] = thread.comments # type: ignore
			# Look for the comment in active threads only.
			if thread.status != 'active' and thread.status != 'unknown':
				continue
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
				if c.content == comment:
					return True
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

	def send_comment(self, pr: GitPullRequest, pr_url: str, is_dry_run: bool, pr_author: IdentityRef, comment: str, threads: list[GitPullRequestCommentThread], thread_context: Optional[CommentThreadContext]=None):
		thread = GitPullRequestCommentThread(comments=[Comment(content=comment)], status='active', thread_context=thread_context)
		if not is_dry_run:
			self.logger.info("COMMENTING: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
			project = self.config['project']
			repository_id = pr.repository.id # type: ignore
			self.git_client.create_thread(thread, repository_id, pr.pull_request_id, project=project)
		else:
			self.logger.info("Would comment: \"%s\"\nTitle: \"%s\"\nBy %s (%s)\n%s", comment, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

		threads.append(thread)

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


def main():
	config_path = sys.argv[1]
	runner = Runner(config_path)
	runner.run()


if __name__ == '__main__':
	main()
