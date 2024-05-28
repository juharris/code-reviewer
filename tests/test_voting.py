from voting import APPROVE_VOTE, NO_VOTE, is_vote_allowed, map_int_vote, map_vote


def test_map_vote():
    assert map_vote(None) is None
    assert map_vote(10) == APPROVE_VOTE
    assert map_vote(APPROVE_VOTE) == APPROVE_VOTE
    assert map_vote(-10) == -10

    assert map_vote('reject') == -10
    assert map_vote('wait') == -5
    assert map_vote('reset') == NO_VOTE
    assert map_vote('approve_with_suggestions') == 5
    assert map_vote('approve') == APPROVE_VOTE

    assert map_vote('other') is None


def test_map_int_vote():
    assert map_int_vote(-20) is None
    assert map_int_vote(20) is None

    assert map_int_vote(APPROVE_VOTE) == 'APPROVE'
    assert map_int_vote(5) == 'approve_with_suggestions'
    assert map_int_vote(NO_VOTE) == 'reset'
    assert map_int_vote(-5) == 'wait'
    assert map_int_vote(-10) == 'REJECT'


def test_allow_cote():
    assert not is_vote_allowed(None, None)

    assert is_vote_allowed(None, -10)
    assert is_vote_allowed(None, -5)
    assert is_vote_allowed(None, NO_VOTE)
    assert is_vote_allowed(None, +5)
    assert is_vote_allowed(None, APPROVE_VOTE)

    assert not is_vote_allowed(-10, None)
    assert not is_vote_allowed(-5, None)
    assert not is_vote_allowed(NO_VOTE, None)
    assert not is_vote_allowed(+5, None)
    assert not is_vote_allowed(APPROVE_VOTE, None)

    assert not is_vote_allowed(-10, -10)
    assert not is_vote_allowed(-10, -5)
    assert not is_vote_allowed(-10, NO_VOTE)
    assert not is_vote_allowed(-10, 5)
    assert not is_vote_allowed(-10, APPROVE_VOTE)

    assert is_vote_allowed(-5, -10)
    assert not is_vote_allowed(-5, -5)
    assert not is_vote_allowed(-5, NO_VOTE)
    assert not is_vote_allowed(-5, 5)
    assert not is_vote_allowed(-5, APPROVE_VOTE)

    assert is_vote_allowed(NO_VOTE, -10)
    assert is_vote_allowed(NO_VOTE, -5)
    assert not is_vote_allowed(NO_VOTE, NO_VOTE)
    assert is_vote_allowed(NO_VOTE, 5)
    assert is_vote_allowed(NO_VOTE, APPROVE_VOTE)

    assert is_vote_allowed(5, -10)
    assert is_vote_allowed(5, -5)
    assert is_vote_allowed(5, NO_VOTE)
    assert not is_vote_allowed(5, 5)
    assert not is_vote_allowed(5, APPROVE_VOTE)

    assert is_vote_allowed(APPROVE_VOTE, -10)
    assert is_vote_allowed(APPROVE_VOTE, -5)
    assert is_vote_allowed(APPROVE_VOTE, NO_VOTE)
    assert is_vote_allowed(APPROVE_VOTE, 5)
    assert not is_vote_allowed(APPROVE_VOTE, APPROVE_VOTE)
