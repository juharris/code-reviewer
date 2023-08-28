from voting import map_vote


def test_map_vote():
	assert map_vote(None) is None
	assert map_vote(10) == 10
	assert map_vote(-10) == -10

	assert map_vote('reject') == -10
	assert map_vote('wait') == -5
	assert map_vote('reset') == 0
	assert map_vote('approve_with_suggestions') == 5
	assert map_vote('approve') == 10
