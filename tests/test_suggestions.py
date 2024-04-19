import re

from config import Rule
from suggestions import Suggester


suggester = Suggester()


def _test(expected: str, text: str, rule: Rule):
	Suggester.load_suggestions(rule)

	suggestion = suggester.suggest(text, rule)
	assert suggestion is not None
	suggestion = suggestion.suggestion
	assert suggestion == expected


def test_suggest_trim():
	text = "code code  "
	expected = "code code"

	rule: Rule = {
		'suggestions': [
			{
				'pattern': '^(.*?)\\s+$',
				'replacement': '\\1'
			}
		]
	} # type: ignore
	_test(expected, text, rule)


def test_suggest_trim_group_num():
	text = "code code   "
	expected = "code code"

	rule: Rule = {
		'suggestions': [
			{
				'pattern': '^(.*?)\\s+$',
				'replacement': '\\g<1>'
			}
		]
	} # type: ignore

	_test(expected, text, rule)


def test_suggest_trim_group_name():
	text = "code code\t \t "
	expected = "code code"

	rule: Rule = {
		'suggestions': [
			{
				'pattern': '^(?P<pre>.*?)\\s+$',
				'replacement': '\\g<pre>'
			}
		]
	} # type: ignore

	_test(expected, text, rule)


def test_suggest_trim_only_end():
	text = "code code\t \t "
	expected = "code code"

	rule: Rule = {
		'suggestions': [
			{
				'pattern': '\\s+$',
				'replacement': ''
			}
		]
	} # type: ignore

	_test(expected, text, rule)


def test_suggest_pattern_inside():
	text = "code A B C"
	expected = "code D B C"

	rule: Rule = {
		'suggestions': [
			{
				'pattern': 'A',
				'replacement': 'D'
			}
		]
	} # type: ignore

	_test(expected, text, rule)


def test_multiple_suggestions():
	text = "code for api that makes api good  "
	expected = "code for API that makes API good"

	rule: Rule = {
		'suggestions': [
			{
				'pattern': '^(?P<pre>.*?)\\s+$',
				'replacement': '\\g<pre>'
			},
			{
				'pattern': '^(?P<pre>.*?)\\bapi\\b(?P<post>.*)$',
				'replacement': '\\g<pre>API\\g<post>'
			},
		]
	} # type: ignore

	_test(expected, text, rule)


def test_multiple_sequential_suggestions():
	text = "code"
	expected = "3"

	rule: Rule = {
		'suggestions': [
			{
				'pattern': '^2',
				'replacement': '3'
			},
			{
				'pattern': '^1',
				'replacement': '2'
			},
			{
				'pattern': 'no match',
				'replacement': 'does not matter'
			},
			{
				'pattern': '^code$',
				'replacement': '1'
			},
		]
	} # type: ignore

	_test(expected, text, rule)