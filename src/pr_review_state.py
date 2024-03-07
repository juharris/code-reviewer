from collections import Counter


class PrReviewState:
	"""
	Represents the state of the current iteration that goes through a specific pull request.
	"""

	comment_counts = Counter()
	"""
	The number of times a comment has been posted on a pull request.
	Keys can be `comment_id`s or the `comment` text when there is no `comment_id`.
	"""