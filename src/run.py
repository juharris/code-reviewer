import os
import re
import sys
from typing import Collection

import yaml
from azure.devops.connection import Connection
from azure.devops.released.core import CoreClient
from azure.devops.released.git import (GitClient, GitPullRequest,
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

current_user = config['current_user']

credentials = BasicAuthentication('', personal_access_token)
connection = Connection(base_url=organization_url, creds=credentials)
core_client: CoreClient = connection.clients.get_core_client()
git_client: GitClient = connection.clients.get_git_client()

# See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.0&tabs=HTTP for help with what's possible.

search = GitPullRequestSearchCriteria(repository_id=repository_id, status=status, )
prs: Collection[GitPullRequest] = git_client.get_pull_requests(repository_id, search, project, top=top)

for rule in rules:
	if p:= rule.get('author_pattern'):
		rule['author_regex'] = re.compile(p, re.IGNORECASE)

for pr in prs:
	author: IdentityRef = pr.created_by # type: ignore
	print(f"By {author.display_name} ({author.unique_name})")
	reviewers: Collection[IdentityRefWithVote] = pr.reviewers # type: ignore
	print()
	print("*" * 50)
	print(pr.title)
	print("*" * 50)
	# print("Description:")
	# print(pr.description)
	
	vote = 0
	for reviewer in reviewers:
		# print(reviewer)
		if reviewer.unique_name == current_user:
			vote = reviewer.vote
			break

	if vote != 0:
		# Already voted.
		# TODO Run rules but only comment if that rule has not been given as a comment yet or rule would give a different vote.
		continue

	for rule in rules:
		vote=rule['vote']
		is_match = False
		if (author_regex := rule.get('author_regex')) is not None and (author_regex.match(author.display_name) or author_regex.match(author.unique_name)):
			is_match = True

		# TODO Add more rules.

		print(rule)
		print(f"matches: {is_match}")
		if is_match:
			reviewer = IdentityRefWithVote(vote=vote)
			git_client.create_pull_request_reviewer(reviewer, repository_id, pr.pull_request_id, reviewer_id=None)
				
	
	