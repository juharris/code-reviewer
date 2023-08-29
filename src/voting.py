from typing import Optional


def map_vote(vote: Optional[int | str]) -> Optional[int]:
	if vote is None or isinstance(vote, int):
		return vote
	assert isinstance(vote, str), \
		f"`vote` must be a string. Got: \"{vote}\" with type: {type(vote)}."
	match vote.lower():
		case 'reject':
			return -10
		case 'wait':
			return -5
		case 'none' | 'reset':
			return 0
		case 'approve_with_suggestions':
			return 5
		case 'approve':
			return 10
	return None


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
