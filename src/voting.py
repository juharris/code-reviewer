from typing import Optional
import logging

APPROVE_VOTE = 10
APPROVE_WITH_SUGGESTIONS_VOTE = 5
NO_VOTE = 0
WAIT = -5


def map_vote(vote: Optional[int | str]) -> Optional[int]:
    if vote is None or isinstance(vote, int):
        return vote
    assert isinstance(vote, str), \
        f"`vote` must be a string. Got: \"{vote}\" with type: {type(vote)}."
    match vote.lower():
        case 'reject':
            return -10
        case 'wait':
            return WAIT
        case 'none' | 'reset':
            return NO_VOTE
        case 'approve_with_suggestions':
            return APPROVE_WITH_SUGGESTIONS_VOTE
        case 'approve':
            return APPROVE_VOTE
    return None


def map_vote_to_log_level(vote: int) -> int:
    match vote:
        case -10:
            return logging.ERROR
        case -5:
            return logging.WARNING
        case 0:
            return logging.INFO
        case 5 | 10:
            return logging.DEBUG
    return logging.INFO


def map_int_vote(vote: int) -> str | None:
    match vote:
        case -10:
            return 'REJECT'
        case -5:
            return 'wait'
        case 0:
            return 'reset'
        case 5:
            return 'approve_with_suggestions'
        case 10:
            return 'APPROVE'
    return None


def is_vote_allowed(current_vote: int | None, new_vote: int | None) -> bool:
    """
    Only vote if the new vote is more rejective (more negative) than the current vote,
    the current vote is not set and the new vote is approve or approve with suggestions.
    This is to avoid approving if someone has already voted.
    """
    return new_vote is not None \
        and (current_vote is None
             or new_vote < current_vote
             or (current_vote == NO_VOTE and new_vote > current_vote))
