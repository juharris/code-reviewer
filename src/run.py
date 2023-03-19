from typing import Collection
import os

from azure.devops.connection import Connection
from azure.devops.released.core import CoreClient
from azure.devops.released.git import GitClient, GitPullRequest, GitPullRequestSearchCriteria
from msrest.authentication import BasicAuthentication

# Fill in with your personal access token and org URL
personal_access_token = os.environ['CR_ADO_PAT']
organization_url = 'https://dev.azure.com/msasg'

# Create a connection to the org
credentials = BasicAuthentication('', personal_access_token)
connection = Connection(base_url=organization_url, creds=credentials)

# Get a client (the "core" client provides access to projects, teams, etc)
core_client: CoreClient = connection.clients.get_core_client()
git_client: GitClient = connection.clients.get_git_client()

search = GitPullRequestSearchCriteria(repository_id='TuringBot', status='Active')
prs: Collection[GitPullRequest] = git_client.get_pull_requests('TuringBot', search, 'Falcon', top=100)
for pr in prs:
	print()
	print("*" * 50)
	print(pr.title)
	print("*" * 50)
	print("Description:")
	print(pr.description)
