# code-reviewer
Azure DevOps Code Reviewer

# Setup
Written using Python 3.10

```bash
pip install --requirement requirements.txt
```

Get a PAT: https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows#create-a-pat

Give the PAT the following permissions:
Scopes:
* Code: Full, Status
* Project and Team: Read
* User Profile: Read
* Pull Request Threads: Read

## Config File
You must create a config file.
Example:
Fill in the values in `{}` with your own values.
```yaml
organization_url: 'https://dev.azure.com/{organization}'
project: {project_name}
repository_name: {repository_name}

# The number of pull requests to check in each run.
top: 80

# The status of the pull requests to check.
# Defaults to 'active'.
# status can be 'abandoned', 'active', 'all', 'completed', 'notSet'
# See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.1&tabs=HTTP#pullrequeststatus for more information.
# Note that the script cannot comment on pull requests that are completed because the diff cannot be computed.
status: 'active'

# Eventually the script will try to figure out your email and ID automatically.
# Your email associated with ADO.
# This is used to see if you already voted on a pull request.
current_user: {your email}
# To get your ID,
# Go to your profile (e.g, https://dev.azure.com/{organization}/_usersSettings/about).
# Click on your picture to edit it.
# Right click on the picture in the pop-up modal and "Copy image link".
# The link should have "?id={ID}" in it.
user_id: {your ID}

# Stats
# If enabled, the script can gather commenters statistics.
# is_stats_enabled: true

log_level: INFO

# The amount of seconds to wait after a run of reviewing pull requests.
# If this is not set, then the script will not loop.
wait_after_review_s: 666

# Dry run:
# If true, then the script will not take actions and will just log what it would do at the INFO level.
# Defaults to false.
# is_dry_run: true

# All checks within each rule must match for the rule to be applied.

# Rules can have:
# Checks:
# * author_pattern: A regex pattern that the author's display name or unique name (email) must match.

# * title_pattern: A regex pattern that the title must match.
# * description_pattern: A regex pattern that the description must match.

# * merge_status_pattern: A regex pattern that the merge status must match. Some typical values are: 'conflicts', 'failure', 'queued', 'succeeded'. See https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.0&tabs=HTTP#pullrequestasyncstatus for more information.

# * is_draft: (optional) By default all pull requests are reviewed. If this is set to true, then only draft pull requests will match the rule. If this is set to false, then only published pull requests will match the rule.

# Checking files:
# * file_pattern: A regex pattern that the file path must match.
# * diff_pattern: A regex pattern that a new or modified line must match.

# If all of the checks in a rule match, then any actions specified will be applied.
# Actions:
# * comment (string): A comment to post on the PR or a line in a diff depending on how the rule matches.
# * require (string): The ID of someone to require.
# * vote (int): The vote to give if the rule matches.

# Voting
# The script will only vote if the new vote would be more rejective than your current vote.
# These are the scores that ADO uses for voting:
# * Approve: 10
# * Approved with suggestions: 5
# * No vote: 0
# * Waiting for author: -5
# * Reject: -10

# Examples:
rules:
  # If the title does not start with a tag, then vote -10.
  - vote: -10
    title_pattern: '^(?!\[[^]]{2,}\])'
    comment: "Please add at least one tag in square brackets at the beginning of the pull request title with nothing before the tag, not even whitespace."
  # Check the PR description.
  - vote: -10
    description_pattern: '^.*DELETE THESE COMMENTS'
    comment: "Please remove the comments in the description that should be removed, as they explain. Otherwise, they will appear in email notifications and in the commit once the pull request has been merged."
  # Check a new or modified line in a file.
  - path_pattern: '^.*\.cs$'
    diff_pattern: '^\s*(int|string|var) \S+_\S\S+'
    vote: -5
    comment: "Automated comment: Please use camelCase for variables and not snake_case. It's important to have consistent and easy to read code as many people contribute to and maintain this repository."
  # Require a reviewer based on the title.
  - title_pattern: '^.*\[bug fix]'
    require: ID    
```

# Running
Run the script:
```bash
CR_ADO_PAT='YOUR PAT' python src/run.py config_path.yml
```

You can also use a config file from a URL (must start with "https://" or "http://"):
```bash
CR_ADO_PAT='YOUR PAT' python src/run.py https://mysite.com/config.yml
```

The script will reload the config file for each run.
A run happens when the script is started and then every `wait_after_review_s` seconds.
