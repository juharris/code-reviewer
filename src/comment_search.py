from dataclasses import dataclass
from typing import Optional

from azure.devops.released.git import Comment, GitPullRequestCommentThread


@dataclass
class CommentSearchResult:
    comment: Comment
    thread: GitPullRequestCommentThread


def get_comment_id_marker(comment_id: Optional[str]) -> str:
    return f'\n<!--code-reviewer comment ID: \"{comment_id}\"-->'
