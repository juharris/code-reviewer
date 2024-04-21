from dataclasses import dataclass, field


@dataclass
class RunState:
	"""
	Represents the state of the current iteration that goes through all rules for all pull requests.
	This is discarded after going through all pull requests.
	"""

	num_requeues: int = field(default=0, init=False)
	"""
	The number of re-queues that have been performed so far in this run across all rules for all pull requests.
	"""
