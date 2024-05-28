from comment_search import get_comment_id_marker


def test_get_comment_id_marker():
    assert get_comment_id_marker(None) == '\n<!--code-reviewer comment ID: \"None\"-->'
    assert get_comment_id_marker('') == '\n<!--code-reviewer comment ID: \"\"-->'
    assert get_comment_id_marker('abc') == '\n<!--code-reviewer comment ID: \"abc\"-->'
    assert get_comment_id_marker('abc \"wtv\"') == '\n<!--code-reviewer comment ID: \"abc \"wtv\"\"-->'
