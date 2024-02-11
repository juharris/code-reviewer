class RunState:
	num_requeues: int = 0
	"""
	The number of re-queues that have been performed so far in this run across all rules for all pull requests.
	"""