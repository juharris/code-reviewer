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
	def __init__(self, config_path: str) -> None:
		self.config_path = config_path

	def run(self):
		while True:
			self.load_config()
			self.review_prs()

			wait_after_review_s = self.config.get('wait_after_review_s')
			if wait_after_review_s is not None:
				logging.debug("Waiting %s seconds before the next review.", wait_after_review_s)
				time.sleep(wait_after_review_s)
			else:
				break

	def load_config(self):
		print(f"Loading configuration from {self.config_path}")
		with open(self.config_path, 'r') as f:
			self.config: Config = yaml.safe_load(f)	

		log_level = logging.getLevelName(self.config.get('log_level', 'INFO'))
		logging.basicConfig(level=log_level)

		rules = self.config['rules']
		for rule in rules:
			for name in ('author',) + attributes_with_patterns:
				if pat := rule.get(f'{name}_pattern'):
					rule[f'{name}_regex'] = re.compile(pat, re.IGNORECASE) # type: ignore
			if pat := rule.get('diff_pattern'):
				rule['diff_regex'] = re.compile(pat, re.MULTILINE)
			if pat := rule.get('path_pattern'):
				rule['path_regex'] = re.compile(pat)

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
		# profile_client: ProfileClient = connection.clients.get_profile_client()
		# r = profile_client.get_profile('me')

		status = self.config.get('status', 'Active')
		top = self.config.get('top', 50)
		# TODO Remove (just for testing)
		source_ref = None
		search = GitPullRequestSearchCriteria(repository_id=repository_name, status=status, source_ref_name=source_ref)
		prs: Collection[GitPullRequest] = self.git_client.get_pull_requests(repository_name, search, project, top=top)
		for pr in prs:
			pr_url = f"{organization_url}/{project}/_git/{repository_name}/pullrequest/{pr.pull_request_id}"
			try:
				self.review_pr(pr, pr_url)
			except:
				logging.exception(f"Error while reviewing pull request called \"{pr.title}\" at {pr_url}")


	def review_pr(self, pr: GitPullRequest, pr_url: str):
		project = self.config['project']
		repository_id = pr.repository.id # type: ignore
		rules = self.config['rules']

		# TODO Try to automate getting the current user email and ID.
		current_user = self.config['current_user']
		user_id = self.config['user_id']
		is_dry_run = self.config.get('is_dry_run', False)

		pr_author: IdentityRef = pr.created_by # type: ignore
		reviewers: Collection[IdentityRefWithVote] = pr.reviewers # type: ignore
		logging.debug(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)

		file_diffs = self.get_diffs(pr, pr_url, rules)

		current_vote = None
		reviewer: Optional[IdentityRefWithVote] = None
		for reviewer in reviewers:
			if reviewer.unique_name == current_user:
				current_vote = reviewer.vote
				break

		threads: Optional[list[GitPullRequestCommentThread]] = None
		for rule in rules:
			# All checks must match.
			vote = rule.get('vote')
			comment = rule.get('comment')
			if (author_regex := rule.get('author_regex')) is not None:
				if not author_regex.match(pr_author.display_name) and not author_regex.match(pr_author.unique_name):
					continue

			match_found = True
			for name in attributes_with_patterns:
				if (regex := rule.get(f'{name}_regex')) is not None:
					if not regex.match(getattr(pr, name)):
						match_found = False
						break

			if not match_found:
				continue

			if (diff_regex := rule.get('diff_regex')) is not None and comment:
				for file_diff in file_diffs:
					for block in file_diff.diff['blocks']:
						change_type = block['changeType']
						if change_type == 0 or change_type == 2 or change_type == 3:
							continue
						assert change_type == 1, f"Unexpected change type: {change_type}"
						for line_num, line in enumerate(block['mLines'], start=block['mLine']):
							if (m := diff_regex.match(line)):
								match_found = True
								# TODO Comment if not already commented on the line.
								threads = threads or self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
								# TODO Make sure we're getting the right position because the context of the comment hides some of the content of the actual line.
								thread_context = CommentThreadContext(file_diff.modified_path, right_file_start=CommentPosition(line_num, m.pos), right_file_end=CommentPosition(line_num, m.endpos))
								self.send_comment(pr, pr_url, is_dry_run, pr_author, comment, threads, thread_context)
			
			if not match_found:
				continue

			logging.debug("Rule matches: %s", rule)
			# Can't vote on a draft.
			# Only vote if the new vote is more rejective (more negative) than the current vote.
			if not pr.is_draft and vote is not None and vote < current_vote:
				current_vote = vote
				logging.info(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
				if not is_dry_run:
					logging.info("Setting vote: %d", vote)
					reviewer = reviewer or IdentityRefWithVote(id=user_id)
					reviewer.vote = vote
					self.git_client.create_pull_request_reviewer(reviewer, repository_id, pr.pull_request_id, reviewer_id=user_id, project=project)
				else:
					logging.info("Would set vote: %d", vote)

			# Don't comment on the PR overview for an issue with a diff.
			if comment is not None and diff_regex is None:
				# Check to see if it's already commented in an active thread.
				# Eventually we could try to find the thread with the comment and reactivate the thread, and/or reply again.
				has_comment = False
				threads = threads or self.git_client.get_threads(repository_id, pr.pull_request_id, project=project)
				has_comment = self.does_comment_exist(threads, comment)
				if not has_comment:
					self.send_comment(pr, pr_url, is_dry_run, pr_author, comment, threads)

	def get_diffs(self, pr: GitPullRequest, pr_url: str, rules: list[Rule]) -> list[FileDiff]:
		result = []
		latest_commit = pr.last_merge_source_commit
		if latest_commit == pr_url_to_latest_commit_seen.get(pr_url):
			logging.debug("Skipping checking diff for commit already seen (%s).", latest_commit)
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
			if not item.get('isFolder'):
				original_path = item['path']
				modified_path = change.get('sourceServerItem', original_path)
				if not any(regex.match(modified_path) for regex in path_regexs):
					continue

				if change_type in ('add', 'edit'):
					# Use an undocumented API.
					# Found at https://stackoverflow.com/questions/41713616
					logging.debug("Checking %s", modified_path)
					diff_url =f'{organization_url}/{project}/_api/_versioncontrol/fileDiff?__v=5&diffParameters={{"originalPath":"{original_path}","originalVersion":"{diffs.base_commit}","modifiedPath":"{modified_path}","modifiedVersion":"{diffs.target_commit}","partialDiff":true,"includeCharDiffs":false}}&repositoryId={repository_id}'
					try:
						diff_request = requests.get(diff_url, auth=('', personal_access_token))
						diff_request.raise_for_status()
						diff = diff_request.json()
						result.append(FileDiff(original_path, modified_path, diff))
					except:
						logging.exception("Failed to get diff for \"%s\". Change type: '%s'", modified_path, change_type)
				else:
					logging.debug("Skipping diff for \"%s\". Change type: '%s'", modified_path, change_type)
		return result

	def does_comment_exist(self, threads: list[GitPullRequestCommentThread], comment: str) -> bool:
		result = False
		assert threads is not None
		for thread in threads:
			comments: Collection[Comment] = thread.comments # type: ignore
			# Look for the comment in active threads only.
			if thread.status != 'active' and thread.status != 'unknown':
				continue
			for c in comments:
				if c.content == comment:
					return True
		return result

	def send_comment(self, pr: GitPullRequest, pr_url: str, is_dry_run: bool, pr_author: IdentityRef, comment: str, threads: list[GitPullRequestCommentThread], thread_context: Optional[CommentThreadContext]=None):
		thread = GitPullRequestCommentThread(comments=[Comment(content=comment)], status='active', thread_context=thread_context)
		logging.info(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, pr_author.display_name, pr_author.unique_name, pr_url)
		if not is_dry_run:
			logging.info("Commenting: \"%s\".", comment)
			project = self.config['project']
			repository_id = pr.repository.id # type: ignore
			self.git_client.create_thread(thread, repository_id, pr.pull_request_id, project=project)
		else:
			logging.info("Would comment: \"%s\".", comment)
		threads.append(thread)


def main():
	config_path = sys.argv[1]
	runner = Runner(config_path)
	runner.run()


if __name__ == '__main__':
	main()
