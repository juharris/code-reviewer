import logging
import os
import re
import sys
from typing import Collection

import yaml
from azure.devops.connection import Connection
from azure.devops.released.core import CoreClient
from azure.devops.released.git import (Comment, GitClient, GitPullRequest,
									   GitPullRequestCommentThread,
									   GitPullRequestSearchCriteria,
									   IdentityRef, IdentityRefWithVote)
from msrest.authentication import BasicAuthentication

config_path = sys.argv[1]
print("Loading configuration from ", config_path)
with open(config_path, 'r') as f:
	config = yaml.safe_load(f)

personal_access_token = config.get('PAT') or os.environ['CR_ADO_PAT']
organization_url = config['organization_url']
project = config['project']
repository_id = config['repository_id']
status = config.get('status', 'Active')
rules = config['rules']
top = config.get('top', 50)

log_level = logging.getLevelName(config.get('log_level', 'INFO'))
logging.basicConfig(level=log_level)

current_user = config['current_user']
user_id = config['user_id']

credentials = BasicAuthentication('', personal_access_token)
connection = Connection(base_url=organization_url, creds=credentials)
core_client: CoreClient = connection.clients.get_core_client()
git_client: GitClient = connection.clients.get_git_client()

# See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.0&tabs=HTTP for help with what's possible.

search = GitPullRequestSearchCriteria(repository_id=repository_id, status=status, )
prs: Collection[GitPullRequest] = git_client.get_pull_requests(repository_id, search, project, top=top)

attributes_with_patterns = ('description', 'title')
for rule in rules:
	for name in ('author',) + attributes_with_patterns:
		if pat := rule.get(f'{name}_pattern'):
			rule[f'{name}_regex'] = re.compile(pat, re.IGNORECASE)

start_log = "*" * 100

for pr in prs:
	author: IdentityRef = pr.created_by # type: ignore
	reviewers: Collection[IdentityRefWithVote] = pr.reviewers # type: ignore
	logging.info(f"\n%s\n%s\n%s\nBy %s (%s)", start_log, pr.title, pr.url, author.display_name, author.unique_name)

	vote = 0
	for reviewer in reviewers:
		if reviewer.unique_name == current_user:
			vote = reviewer.vote
			break

	if vote != 0:
		logging.debug("You already voted on \"%s\".", pr.title)
		# Already voted.
		# TODO Run rules but only comment if that rule has not been given as a comment yet or rule would give a different vote.
		continue

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

		logging.info("Rule matches: %s", rule)
		if not pr.is_draft and vote is not None:
			logging.info("Setting vote: %d", vote)
			reviewer = IdentityRefWithVote(id=user_id, vote=vote)
			git_client.create_pull_request_reviewer(reviewer, repository_id, pr.pull_request_id, reviewer_id=user_id, project=project)
		if comment is not None:
			# TODO Check to see if it's already commented, reactivate the thread, and maybe reply again.
			logging.info("Commenting: \"%s\"", comment)
			thread = GitPullRequestCommentThread(comments=[Comment(content=comment)])
			git_client.create_thread(thread, repository_id, pr.pull_request_id, project=project)