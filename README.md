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

# Run
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

# Eventually the script will try to figure out your email and ID automatically.
# Your email associated with ADO.
# This is used to see if you already voted on a pull request.
current_user: {your email}
# To get your ID, you can right click on your picture in Azure DevOps and click "Copy image link".
user_id: {your id}

log_level: INFO

# The amount of seconds to wait after a run of reviewing pull requests.
# If this is not set, then the script will not loop.
wait_after_review_s: 666

# is_dry_run: true

# Voting
# The script will only vote if the new vote would be more rejective than your current vote.
# These are the scores that ADO uses for voting:
# * Approve: 10
# * Approved with suggestions: 5
# * No vote: 0
# * Waiting for author: -5
# * Reject: -10

# All checks within each rule must match for the rule to be applied.
rules:
    # If the title does not start with a tag, then vote -10.
  - vote: -10
    title_pattern: '^(?!\[[^]]{2,}\])'
    comment: "Please add at least one tag in square brackets at the beginning of the pull request title with nothing before the tag, not even whitespace."
    # Check the PR description.
  - vote: -10
    description_pattern: '^.*DELETE THESE COMMENTS'
    comment: "Please remove the comments in the description that should be removed, as they explain. Otherwise, they will appear in email notifications and in the commit once the pull request has been merged."
```

Run the script:
```bash
CR_ADO_PAT='YOUR PAT' python src/run.py config_path.yml
```

