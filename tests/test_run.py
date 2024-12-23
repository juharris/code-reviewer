from datetime import datetime
import os
from unittest import mock

from azure.devops.released.git import (
    Comment,
    GitCommitDiffs,
    GitCommitRef,
    GitPullRequest,
    GitPullRequestCommentThread,
    GitPullRequestIteration,
    GitRepository,
    IdentityRef,
    IdentityRefWithVote,
)
from injector import Injector
import requests

from config.config_module import ConfigModule
from file_diff import Block, Diff
from logger import LoggingModule
from run import Runner
from voting import APPROVE_VOTE, NO_VOTE, WAIT_VOTE


TESTS_DIR = os.path.dirname(__file__)


def test_review_pr_no_rules_reset_votes_after_changes_no_reset():
    """
    This tests the scenario where there is a manual vote on a PR that should not be reset.
    """
    config_path = os.path.join(TESTS_DIR, "configs/no_rules_reset_votes_after_changes.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.git_client = mock.MagicMock()
    runner.git_client.get_threads.return_value = [
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 19),
            properties={"CodeReviewVoteResult": {"$value": WAIT_VOTE}},
        ),
    ]
    runner.git_client.get_pull_request_iterations.return_value = [
        GitPullRequestIteration(updated_date=datetime(2024, 12, 18)),
    ]

    # The PR ID should be unique across test cases.
    pr_id = 100100
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        is_draft=False,
        # Reusing the PR ID as the commit ID to ensure unique commit IDs across test cases.
        last_merge_source_commit=GitCommitRef(commit_id=str(pr_id)),
        pull_request_id=pr_id,
        repository=GitRepository(),
        reviewers=[
            IdentityRefWithVote(id=runner.config["user_id"], vote=WAIT_VOTE),
        ],
        source_ref_name=f"branch{pr_id}",
        status="active",
        target_ref_name="master",
    )
    pr_url = f"https://example.com/pr/{pr_id}"

    runner.review_pr(pr, pr_url, run_state=None)

    runner.git_client.create_pull_request_reviewer.assert_not_called()


@mock.patch.object(requests, "get")
def test_review_pr_vote_based_on_diff_pattern_reset(mock_requests_get):
    """
    This tests the scenario where there's a rule that votes based on a diff pattern and the vote has already been
    applied to the PR and a new iteration was pushed and now the vote needs to be reset.
    """
    config_path = os.path.join(TESTS_DIR, "configs/vote_based_on_diff_pattern.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.git_client = mock.MagicMock()
    runner.git_client.get_threads.return_value = [
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 19),
            properties={"CodeReviewVoteResult": {"$value": WAIT_VOTE}},
        ),
    ]
    runner.git_client.get_pull_request_iterations.return_value = [
        GitPullRequestIteration(updated_date=datetime(2024, 12, 18)),
        GitPullRequestIteration(updated_date=datetime(2024, 12, 20)),
    ]
    runner.git_client.get_commit_diffs.return_value = GitCommitDiffs(
        changes=[{
            "changeType": "edit",
            "item": {
                "isFolder": False,
                "path": "foo.py",
            },
        }],
    )
    diff = Diff(blocks=[Block(
        changeType=1,
        mLines=["    bar = foo.new_method()"],
        mLine=5,
        mLinesCount=1,
    )])
    mock_diff_response = mock.MagicMock()
    mock_diff_response.json.return_value = diff
    mock_requests_get.return_value = mock_diff_response

    # The PR ID should be unique across test cases.
    pr_id = 110110
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        is_draft=False,
        # Reusing the PR ID as the commit ID to ensure unique commit IDs across test cases.
        last_merge_source_commit=GitCommitRef(commit_id=str(pr_id)),
        pull_request_id=pr_id,
        repository=GitRepository(),
        reviewers=[
            IdentityRefWithVote(id=runner.config["user_id"], vote=WAIT_VOTE),
        ],
        source_ref_name=f"branch{pr_id}",
        status="active",
        target_ref_name="master",
    )
    pr_url = f"https://example.com/pr/{pr_id}"

    runner.review_pr(pr, pr_url, run_state=None)

    runner.git_client.create_pull_request_reviewer.assert_called_once()
    call_args = runner.git_client.create_pull_request_reviewer.call_args
    assert call_args.args[0].id == runner.config["user_id"]
    assert call_args.args[0].vote == NO_VOTE
    assert call_args.args[2] == pr_id
    assert call_args.kwargs.get("reviewer_id") == runner.config["user_id"]


@mock.patch.object(requests, "get")
def test_review_pr_vote_based_on_diff_pattern_no_reset(mock_requests_get):
    """
    This tests the scenario where there's a rule that votes based on a diff pattern and the vote has already been
    applied to the PR and a new iteration was pushed, but another vote was cast manually, so it should not be reset.
    """
    config_path = os.path.join(TESTS_DIR, "configs/vote_based_on_diff_pattern.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.git_client = mock.MagicMock()
    runner.git_client.get_threads.return_value = [
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 19),
            properties={"CodeReviewVoteResult": {"$value": WAIT_VOTE}},
        ),
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 21),
            properties={"CodeReviewVoteResult": {"$value": APPROVE_VOTE}},
        ),
    ]
    runner.git_client.get_pull_request_iterations.return_value = [
        GitPullRequestIteration(updated_date=datetime(2024, 12, 18)),
        GitPullRequestIteration(updated_date=datetime(2024, 12, 20)),
    ]
    runner.git_client.get_commit_diffs.return_value = GitCommitDiffs(
        changes=[{
            "changeType": "edit",
            "item": {
                "isFolder": False,
                "path": "foo.py",
            },
        }],
    )
    diff = Diff(blocks=[Block(
        changeType=1,
        mLines=["    bar = foo.new_method()"],
        mLine=5,
        mLinesCount=1,
    )])
    mock_diff_response = mock.MagicMock()
    mock_diff_response.json.return_value = diff
    mock_requests_get.return_value = mock_diff_response

    # The PR ID should be unique across test cases.
    pr_id = 120120
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        is_draft=False,
        # Reusing the PR ID as the commit ID to ensure unique commit IDs across test cases.
        last_merge_source_commit=GitCommitRef(commit_id=str(pr_id)),
        pull_request_id=pr_id,
        repository=GitRepository(),
        reviewers=[
            IdentityRefWithVote(id=runner.config["user_id"], vote=APPROVE_VOTE),
        ],
        source_ref_name=f"branch{pr_id}",
        status="active",
        target_ref_name="master",
    )
    pr_url = f"https://example.com/pr/{pr_id}"

    runner.review_pr(pr, pr_url, run_state=None)

    runner.git_client.create_pull_request_reviewer.assert_not_called()


@mock.patch.object(requests, "get")
def test_review_pr_vote_based_on_description_vote(mock_requests_get):
    """
    This tests the scenario where there's a rule that votes based on the PR description and the rule matches.
    """
    config_path = os.path.join(TESTS_DIR, "configs/vote_based_on_description.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.git_client = mock.MagicMock()
    runner.git_client.get_threads.return_value = []
    runner.git_client.get_pull_request_iterations.return_value = [
        GitPullRequestIteration(updated_date=datetime(2024, 12, 18)),
    ]

    # The PR ID should be unique across test cases.
    pr_id = 130130
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        description="This is a bad description containing the forbidden phrase.",
        is_draft=False,
        # Reusing the PR ID as the commit ID to ensure unique commit IDs across test cases.
        last_merge_source_commit=GitCommitRef(commit_id=str(pr_id)),
        pull_request_id=pr_id,
        repository=GitRepository(),
        reviewers=[],
        source_ref_name=f"branch{pr_id}",
        status="active",
        target_ref_name="master",
    )
    pr_url = f"https://example.com/pr/{pr_id}"

    runner.review_pr(pr, pr_url, run_state=None)

    runner.git_client.create_pull_request_reviewer.assert_called_once()
    call_args = runner.git_client.create_pull_request_reviewer.call_args
    assert call_args.args[0].id == runner.config["user_id"]
    assert call_args.args[0].vote == WAIT_VOTE
    assert call_args.args[2] == pr_id
    assert call_args.kwargs.get("reviewer_id") == runner.config["user_id"]


def test_review_pr_vote_based_on_description_reset():
    """
    This tests the scenario where there's a rule that votes based on the PR description and the vote has already been
    applied to the PR and the PR description was updated and now the vote needs to be reset.
    """
    config_path = os.path.join(TESTS_DIR, "configs/vote_based_on_description.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.git_client = mock.MagicMock()
    runner.git_client.get_threads.return_value = [
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 19),
            properties={"CodeReviewVoteResult": {"$value": WAIT_VOTE}},
        ),
    ]
    runner.git_client.get_pull_request_iterations.return_value = [
        GitPullRequestIteration(updated_date=datetime(2024, 12, 18)),
    ]

    # The PR ID should be unique across test cases.
    pr_id = 140140
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        description="This is a good description.",
        is_draft=False,
        # Reusing the PR ID as the commit ID to ensure unique commit IDs across test cases.
        last_merge_source_commit=GitCommitRef(commit_id=str(pr_id)),
        pull_request_id=pr_id,
        repository=GitRepository(),
        reviewers=[
            IdentityRefWithVote(id=runner.config["user_id"], vote=WAIT_VOTE),
        ],
        source_ref_name=f"branch{pr_id}",
        status="active",
        target_ref_name="master",
    )
    pr_url = f"https://example.com/pr/{pr_id}"

    runner.review_pr(pr, pr_url, run_state=None)

    runner.git_client.create_pull_request_reviewer.assert_called_once()
    call_args = runner.git_client.create_pull_request_reviewer.call_args
    assert call_args.args[0].id == runner.config["user_id"]
    assert call_args.args[0].vote == NO_VOTE
    assert call_args.args[2] == pr_id
    assert call_args.kwargs.get("reviewer_id") == runner.config["user_id"]


def test_review_pr_vote_based_on_description_no_double_reset():
    """
    This tests that the vote won't be reset again if it's already been reset before.
    """
    config_path = os.path.join(TESTS_DIR, "configs/vote_based_on_description.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.git_client = mock.MagicMock()
    runner.git_client.get_threads.return_value = [
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 19),
            properties={"CodeReviewVoteResult": {"$value": WAIT_VOTE}},
        ),
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 20),
            properties={"CodeReviewVoteResult": {"$value": NO_VOTE}},
        ),
    ]
    runner.git_client.get_pull_request_iterations.return_value = [
        GitPullRequestIteration(updated_date=datetime(2024, 12, 18)),
    ]

    # The PR ID should be unique across test cases.
    pr_id = 150150
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        description="This is a good description.",
        is_draft=False,
        # Reusing the PR ID as the commit ID to ensure unique commit IDs across test cases.
        last_merge_source_commit=GitCommitRef(commit_id=str(pr_id)),
        pull_request_id=pr_id,
        repository=GitRepository(),
        reviewers=[
            IdentityRefWithVote(id=runner.config["user_id"], vote=NO_VOTE),
        ],
        source_ref_name=f"branch{pr_id}",
        status="active",
        target_ref_name="master",
    )
    pr_url = f"https://example.com/pr/{pr_id}"

    runner.review_pr(pr, pr_url, run_state=None)

    runner.git_client.create_pull_request_reviewer.assert_not_called()
