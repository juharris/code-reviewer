import logging
import os
import pdb
import re
import sys
import time
from typing import Collection, Optional

import requests
import yaml
from azure.devops.connection import Connection
from azure.devops.released.git import (Comment, GitBaseVersionDescriptor,
                                       GitClient, GitCommitDiffs,
                                       GitPullRequest, GitPullRequestChange,
                                       GitPullRequestCommentThread,
                                       GitPullRequestIterationChanges,
                                       GitPullRequestSearchCriteria,
                                       GitTargetVersionDescriptor, IdentityRef,
                                       IdentityRefWithVote)
from azure.devops.released.profile.profile_client import ProfileClient
from msrest.authentication import BasicAuthentication

# See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.0&tabs=HTTP for help with what's possible.

branch_pat = re.compile('^refs/heads/')

log_start = "*" * 100
attributes_with_patterns = ('description', 'title')
pr_url_to_latest_commit_seen = {}

def load_config(config_path: str) -> dict:
	print(f"Loading configuration from {config_path}")
	with open(config_path, 'r') as f:
		result = yaml.safe_load(f)	

	log_level = logging.getLevelName(result.get('log_level', 'INFO'))
	logging.basicConfig(level=log_level)

	rules = result['rules']
	for rule in rules:
		for name in ('author',) + attributes_with_patterns:
			if pat := rule.get(f'{name}_pattern'):
				rule[f'{name}_regex'] = re.compile(pat, re.IGNORECASE)
	return result



def review_prs(config: dict):
	personal_access_token = config.get('PAT')
	if not personal_access_token:
		personal_access_token = os.environ.get('CR_ADO_PAT')
		config['PAT'] = personal_access_token

	if not personal_access_token:
		raise ValueError("No personal access token provided. Please set the CR_ADO_PAT environment variable or add set 'PAT' the config file.")

	credentials = BasicAuthentication('', personal_access_token)

	organization_url = config['organization_url']
	project = config['project']
	repository_id = None # Probably not needed now: config.get('repository_id')
	repository_name = config['repository_name']
	connection = Connection(base_url=organization_url, creds=credentials)
	git_client: GitClient = connection.clients.get_git_client()
	# TODO Try to get the current user's email and ID, but getting auth issues:
	# profile_client: ProfileClient = connection.clients.get_profile_client()
	# r = profile_client.get_profile('me')

	status = config.get('status', 'Active')
	top = config.get('top', 50)
	# TODO Remove (just for testing)
	source_ref = None#
	search = GitPullRequestSearchCriteria(repository_id=repository_name, status=status, source_ref_name=source_ref)
	prs: Collection[GitPullRequest] = git_client.get_pull_requests(repository_name, search, project, top=top)
	for pr in prs:
		pr_url = f"{organization_url}/{project}/_git/{repository_name}/pullrequest/{pr.pull_request_id}"
		review_pr(config, git_client, pr, pr_url)
		# TODO re-add when done testing.
		# try:
		# 	review_pr(config, git_client, pr)
		# except:
		# 	logging.exception(f"Error while reviewing pull request called \"{pr.title}\" at {url}")


def review_pr(config: dict, git_client: GitClient, pr: GitPullRequest, pr_url: str):
	organization_url = config['organization_url']
	project = config['project']
	repository_id = pr.repository.id
	rules = config['rules']
	personal_access_token = config['PAT']

	# TODO Try to automate getting the current user email and ID.
	current_user = config['current_user']
	user_id = config['user_id']
	is_dry_run = config.get('is_dry_run', False)

	author: IdentityRef = pr.created_by # type: ignore
	reviewers: Collection[IdentityRefWithVote] = pr.reviewers # type: ignore
	logging.debug(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, author.display_name, author.unique_name, pr_url)

	# Get the files changed.
	pr_branch = branch_pat.sub('', pr.source_ref_name) # type: ignore
	target = GitTargetVersionDescriptor(target_version=pr_branch, target_version_type='branch')
	# The branch to merge into.
	base_branch = branch_pat.sub('', pr.target_ref_name) # type: ignore
	base = GitBaseVersionDescriptor(base_version=base_branch, base_version_type='branch')

	diffs: GitCommitDiffs = git_client.get_commit_diffs(repository_id, project, diff_common_commit=True, base_version_descriptor=base, target_version_descriptor=target)
	base_commit = diffs.base_commit
	changes: list[dict] = diffs.changes # type: ignore

	file_diffs = []
	for c in changes:
		item = c['item']
		change_type = c['changeType']
		# TODO Handle when change_type has multiple values.
		if not item.get('isFolder') and change_type in ('add', 'edit', 'rename'):
			modified_path =  item['path']
			logging.debug("Checking %s", modified_path)
			# FIXME Get the original path for moved files.
			original_path = item['path']
			diff_url =f'{organization_url}/{project}/_api/_versioncontrol/fileDiff?__v=5&diffParameters={{"originalPath":"{original_path}","originalVersion":"{diffs.target_commit}","modifiedPath":"{modified_path}","modifiedVersion":"{diffs.target_commit}","partialDiff":true,"includeCharDiffs":false}}&repositoryId={repository_id}'
			diff = requests.get(diff_url, auth=('', personal_access_token)).json()

			for block in diff['blocks']:
				# print(block)
				lines = block['mLines']
				# TODO Check for issues on the lines and comment if a rule matches.
			# print(diff)

	# pdb.set_trace()
	# sys.exit(0)
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
			if not author_regex.match(author.display_name) and not author_regex.match(author.unique_name):
				continue

		match_found = True
		for name in attributes_with_patterns:
			if (regex := rule.get(f'{name}_regex')) is not None:
				if not regex.match(getattr(pr, name)):
					match_found = False
					break
		if not match_found:
			continue

		# TODO Add more rules.

		logging.debug("Rule matches: %s", rule)
		# Can't vote on a draft.
		# Only vote if the new vote is more rejective (more negative) than the current vote.
		if not pr.is_draft and vote is not None and vote < current_vote:
			current_vote = vote
			logging.info(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, author.display_name, author.unique_name, pr_url)
			if not is_dry_run:
				logging.info("Setting vote: %d", vote)
				reviewer = reviewer or IdentityRefWithVote(id=user_id)
				reviewer.vote = vote
				git_client.create_pull_request_reviewer(reviewer, repository_id, pr.pull_request_id, reviewer_id=user_id, project=project)
			else:
				logging.info("Would set vote: %d", vote)

		if comment is not None:
			# Check to see if it's already commented in an active thread.
			# Eventually we could try to find the thread with the comment and reactivate the thread, and/or reply again.
			has_comment = False
			threads = threads or git_client.get_threads(repository_id, pr.pull_request_id, project=project)
			assert threads is not None
			for thread in threads:
				comments: Collection[Comment] = thread.comments # type: ignore
				# Look for the comment in active threads only.
				if thread.status != 'active' and thread.status != 'unknown':
					continue
				for c in comments:
					if c.content == comment:
						has_comment = True
						break
				if has_comment:
					break
			if not has_comment:
				thread = GitPullRequestCommentThread(comments=[Comment(content=comment)], status='active')
				logging.info(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, author.display_name, author.unique_name, pr_url)
				if not is_dry_run:
					logging.info("Commenting: \"%s\".", comment)
					git_client.create_thread(thread, repository_id, pr.pull_request_id, project=project)
				else:
					logging.info("Would comment: \"%s\".", comment)
				threads.append(thread)


def main():
	config_path = sys.argv[1]

	while True:
		config = load_config(config_path)
		review_prs(config)

		wait_after_review_s = config.get('wait_after_review_s')
		if wait_after_review_s is not None:
			logging.debug("Waiting %s seconds before the next review.", wait_after_review_s)
			time.sleep(wait_after_review_s)
		else:
			break


if __name__ == '__main__':
	main()
