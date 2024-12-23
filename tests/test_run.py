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
    WebApiCreateTagRequestData,
    WebApiTagDefinition,
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
    runner.rest_api_kwargs = {}
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
    runner.rest_api_kwargs = {}
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
    runner.rest_api_kwargs = {}
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


def test_review_pr_vote_approve():
    """
    This tests that a rule that sets the vote to the same "approve" value that it's already set to is recognized by
    reset_votes_if_no_rule_votes as having voted.
    """
    config_path = os.path.join(TESTS_DIR, "configs/vote_approve.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.rest_api_kwargs = {}
    runner.git_client = mock.MagicMock()
    runner.git_client.get_threads.return_value = [
        GitPullRequestCommentThread(
            comments=[Comment(author=IdentityRef(id=runner.config["user_id"]))],
            last_updated_date=datetime(2024, 12, 19),
            properties={"CodeReviewVoteResult": {"$value": APPROVE_VOTE}},
        ),
    ]
    runner.git_client.get_pull_request_iterations.return_value = [
        GitPullRequestIteration(updated_date=datetime(2024, 12, 18)),
    ]

    # The PR ID should be unique across test cases.
    pr_id = 155155
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
        title="Auto-format code",
    )
    pr_url = f"https://example.com/pr/{pr_id}"

    runner.review_pr(pr, pr_url, run_state=None)

    runner.git_client.create_pull_request_reviewer.assert_not_called()


def test_review_pr_rule_based_on_vote_no_reset():
    """
    This tests the scenario where a rule checks for a vote that is already present on the PR and then the vote is
    reset because no rule voted.
    """
    config_path = os.path.join(TESTS_DIR, "configs/rule_based_on_vote_no_reset.yml")
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
    runner.git_client.create_pull_request_label.return_value = WebApiTagDefinition(name="wait")

    # The PR ID should be unique across test cases.
    pr_id = 160160
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

    assert pr.labels == [WebApiTagDefinition(name="wait")]
    runner.git_client.create_pull_request_label.assert_called_once()
    call_args = runner.git_client.create_pull_request_label.call_args
    assert call_args.args[0].name == "wait"

    runner.git_client.create_pull_request_reviewer.assert_not_called()


def test_review_pr_rule_based_on_vote_then_reset():
    """
    This tests the scenario where a rule checks for a vote that is already present on the PR and then the vote is
    reset because no rule voted.
    """
    config_path = os.path.join(TESTS_DIR, "configs/rule_based_on_vote_then_reset.yml")
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
    runner.git_client.create_pull_request_label.return_value = WebApiTagDefinition(name="wait")

    # The PR ID should be unique across test cases.
    pr_id = 170170
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

    assert pr.labels == [WebApiTagDefinition(name="wait")]
    runner.git_client.create_pull_request_label.assert_called_once()
    call_args = runner.git_client.create_pull_request_label.call_args
    assert call_args.args[0].name == "wait"

    runner.git_client.create_pull_request_reviewer.assert_called_once()
    call_args = runner.git_client.create_pull_request_reviewer.call_args
    assert call_args.args[0].id == runner.config["user_id"]
    assert call_args.args[0].vote == NO_VOTE
    assert call_args.args[2] == pr_id
    assert call_args.kwargs.get("reviewer_id") == runner.config["user_id"]


@mock.patch.object(requests, "get")
def test_review_pr_both_reset_votes_options_both_reset(mock_requests_get):
    """
    This tests the scenario where both reset_votes_after_changes and reset_votes_if_no_rule_votes are used in the same
    config file and both should trigger a reset of the vote. This tests esp. that the vote isn't attempted to be reset
    twice.
    """
    config_path = os.path.join(TESTS_DIR, "configs/both_reset_votes_options.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.rest_api_kwargs = {}
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
    pr_id = 180180
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


@mock.patch.object(requests, "get")
def test_review_pr_both_reset_votes_options_reset_after_changes(mock_requests_get):
    """
    This tests the scenario where both reset_votes_after_changes and reset_votes_if_no_rule_votes are used in the same
    config file and only reset_votes_after_changes should trigger a reset.
    """
    config_path = os.path.join(TESTS_DIR, "configs/both_reset_votes_options.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.rest_api_kwargs = {}
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

    call_arg_votes = []

    # Use a side_effect to collect the votes in the call args for create_pull_request_reviewer because we reuse the
    # same reviewer object that is passed to the first call and we change the vote value later.
    def mock_create_pull_request_reviewer(*args, **kwargs):
        call_arg_votes.append(args[0].vote)
    runner.git_client.create_pull_request_reviewer.side_effect = mock_create_pull_request_reviewer

    # The PR ID should be unique across test cases.
    pr_id = 190190
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        description="This is a bad description containing the forbidden phrase.",
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

    runner.git_client.create_pull_request_reviewer.call_count == len(call_arg_votes) == 2
    call_args_list = runner.git_client.create_pull_request_reviewer.call_args_list
    assert call_args_list[0].args[0].id == runner.config["user_id"]
    assert call_arg_votes[0] == NO_VOTE
    assert call_args_list[0].args[2] == pr_id
    assert call_args_list[0].kwargs.get("reviewer_id") == runner.config["user_id"]
    assert call_args_list[1].args[0].id == runner.config["user_id"]
    assert call_arg_votes[1] == WAIT_VOTE
    assert call_args_list[1].args[2] == pr_id
    assert call_args_list[1].kwargs.get("reviewer_id") == runner.config["user_id"]


@mock.patch.object(requests, "get")
def test_review_pr_both_reset_votes_options_reset_no_rule_voted(mock_requests_get):
    """
    This tests the scenario where both reset_votes_after_changes and reset_votes_if_no_rule_votes are used in the same
    config file and only reset_votes_if_no_rule_votes should trigger a reset.
    """
    config_path = os.path.join(TESTS_DIR, "configs/both_reset_votes_options.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.rest_api_kwargs = {}
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
    pr_id = 200200
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


@mock.patch.object(requests, "get")
def test_review_pr_both_reset_votes_options_no_reset(mock_requests_get):
    """
    This tests the scenario where both reset_votes_after_changes and reset_votes_if_no_rule_votes are used in the same
    config file and neither should trigger a reset. This also tests that a rule that sets the vote to the same
    (non-NO_VOTE) value that it's already set to is recognized by reset_votes_if_no_rule_votes as having voted.
    """
    config_path = os.path.join(TESTS_DIR, "configs/both_reset_votes_options.yml")
    inj = Injector([
        ConfigModule(config_path),
        LoggingModule,
    ])
    runner = inj.get(Runner)
    reload_info = runner.config_loader.load_config()
    runner.config = reload_info.config
    runner.rest_api_kwargs = {}
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
        mLines=["    bar = foo.deprecated_method()"],
        mLine=5,
        mLinesCount=1,
    )])
    mock_diff_response = mock.MagicMock()
    mock_diff_response.json.return_value = diff
    mock_requests_get.return_value = mock_diff_response

    # The PR ID should be unique across test cases.
    pr_id = 210210
    pr = GitPullRequest(
        created_by=IdentityRef(display_name="P.R. Author"),
        description="This is a bad description containing the forbidden phrase.",
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
