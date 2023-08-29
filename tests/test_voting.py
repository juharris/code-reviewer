from voting import map_int_vote, map_vote


def test_map_vote():
	assert map_vote(None) is None
	assert map_vote(10) == 10
	assert map_vote(-10) == -10

	assert map_vote('reject') == -10
	assert map_vote('wait') == -5
	assert map_vote('reset') == 0
	assert map_vote('approve_with_suggestions') == 5
	assert map_vote('approve') == 10

	assert map_vote('other') == None


def test_map_int_vote():
	assert map_int_vote(-20) is None
	assert map_int_vote(20) is None

	assert map_int_vote(10) == 'APPROVE'
	assert map_int_vote(5) == 'approve_with_suggestions'
	assert map_int_vote(0) == 'reset'
	assert map_int_vote(-5) == 'wait'
	assert map_int_vote(-10) == 'REJECT'
