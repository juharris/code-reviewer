import logging
import os
import re
import sys
import time
from typing import Collection, List, Optional

import yaml
from azure.devops.connection import Connection
from azure.devops.released.core import CoreClient
from azure.devops.released.git import (Comment, GitClient, GitPullRequest,
                                       GitPullRequestCommentThread,
                                       GitPullRequestSearchCriteria,
                                       IdentityRef, IdentityRefWithVote)
from msrest.authentication import BasicAuthentication



# See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.0&tabs=HTTP for help with what's possible.

log_start = "*" * 100
attributes_with_patterns = ('description', 'title')

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
	personal_access_token = config.get('PAT') or os.environ['CR_ADO_PAT']
	credentials = BasicAuthentication('', personal_access_token)

	organization_url = config['organization_url']
	project = config['project']
	repository_id = config['repository_id']
	connection = Connection(base_url=organization_url, creds=credentials)
	git_client: GitClient = connection.clients.get_git_client()

	status = config.get('status', 'Active')
	top = config.get('top', 50)
	search = GitPullRequestSearchCriteria(repository_id=repository_id, status=status, )
	prs: Collection[GitPullRequest] = git_client.get_pull_requests(repository_id, search, project, top=top)
	for pr in prs:
		try:
			review_pr(config, git_client, pr)
		except:
			url = f"{organization_url}/{project}/_git/{repository_id}/pullrequest/{pr.pull_request_id}"
			logging.exception(f"Error while reviewing pull request called \"{pr.title}\" at {url}")


def review_pr(config: dict, git_client: GitClient, pr: GitPullRequest):
	organization_url = config['organization_url']
	project = config['project']
	repository_id = config['repository_id']
	rules = config['rules']

	current_user = config['current_user']
	user_id = config['user_id']
	is_dry_run = config.get('is_dry_run', False)

	author: IdentityRef = pr.created_by # type: ignore
	reviewers: Collection[IdentityRefWithVote] = pr.reviewers # type: ignore
	url = f"{organization_url}/{project}/_git/{repository_id}/pullrequest/{pr.pull_request_id}"
	logging.debug(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, author.display_name, author.unique_name, url)

	current_vote = None
	reviewer: Optional[IdentityRefWithVote] = None
	for reviewer in reviewers:
		if reviewer.unique_name == current_user:
			current_vote = reviewer.vote
			break

	threads: Optional[List[GitPullRequestCommentThread]] = None
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
			logging.info(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, author.display_name, author.unique_name, url)
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
				logging.info(f"\n%s\n%s\nBy %s (%s)\n%s", log_start, pr.title, author.display_name, author.unique_name, url)
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
