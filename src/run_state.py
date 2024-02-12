class RunState:
	"""
	Represents the state of the current iteration that goes through all rules for all pull requests.
	Resets after going through all pull requests.
	"""

	num_requeues: int = 0
	"""
	The number of re-queues that have been performed so far in this run across all rules for all pull requests.
	"""