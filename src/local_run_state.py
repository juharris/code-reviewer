from dataclasses import dataclass, field


@dataclass
class LocalReviewRunState:
	"""
	Represents the state of the current iteration that goes through all rules for all files.
	This is discarded after going through all files.
	"""

	error_level: int = field(default=0, init=False)
	"""
	The highest error level encountered so far in this run across all rules for all files.
	"""
