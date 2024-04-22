import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Collection, Iterable, Literal, Optional

from injector import inject
from tqdm import tqdm

from config import Config, Rule
from local_run_state import LocalReviewRunState
from suggestions import Suggester
from voting import map_vote, map_vote_to_log_level


@dataclass
class FileInfo:
	path: str
	contents: Optional[str] = None


@dataclass
class RunOptions:
	paths: Collection[str]
	severity: Literal['none'] | Literal['wait'] | Literal['REJECT']
	fix: bool


@inject
@dataclass
class LocalReviewer:
	config: Config
	logger: logging.Logger
	suggester: Suggester

	def get_files(self, paths: Iterable[str]) -> Collection[str]:
		result = []
		for path in paths:
			if os.path.isdir(path):
				result.extend(self.get_files(os.path.join(path, f) for f in os.listdir(path)))
			else:
				result.append(path)
		return result

	def review_file(self, state: LocalReviewRunState, path: str):
		rules = self.config.get('rules')
		assert rules is not None
		f = FileInfo(path)
		for rule in rules:
			self.run_rule_for_file(state, f, rule)

	def run(self, options: RunOptions) -> None:
		if options.fix:
			raise NotImplementedError("Modifying files is not supported yet.")
		sev = map_vote(options.severity)
		assert sev is not None, f"Expected severity to be a string for a vote. Got: \"{options.severity}\"."
		paths = self.get_files(options.paths)
		state = LocalReviewRunState()
		for path in tqdm(paths,
			desc="Reviewing files",
			unit_scale=True, mininterval=2, unit=" files"
		):
			self.review_file(state, path)
		if state.error_level <= sev:
			self.logger.error("Exiting with error level 1 because problems were found.")
			sys.exit(1)

	def run_rule_for_file(self, state: LocalReviewRunState, file_info: FileInfo, rule: Rule) -> None:
		p = rule.get('path_regex')
		path = file_info.path
		if p is not None and not p.match(path):
			return
		diff_regex = rule.get('diff_regex')
		if diff_regex is not None:
			vote = rule.get('vote', 0)
			assert isinstance(vote, int), f"Expected vote to be an int. Got: {vote} ({type(vote)})"
			log_level = map_vote_to_log_level(vote)
			comment = rule.get('comment')
			if comment is not None:
				comment = f"\n{comment}"
			else:
				comment = ""
			# Avoid re-opening the file for each rule.
			if file_info.contents is None:
				# Purposely assume and enforce a sane encoding for now. Can revisit later.
				with open(path, 'r', encoding='utf8') as f:
					file_info.contents = f.read()

			first_line_num = 1
			for line_num, line in enumerate(file_info.contents.splitlines(), start=first_line_num):
				line = line.rstrip('\r\n')
				if diff_regex.match(line):
					suggestion = self.suggester.get_suggestion(line, rule)
					self.logger.log(log_level, "%s (%d): \"%s\" matches '%s'.%s%s", path, line_num, line, diff_regex.pattern, comment, suggestion)
					state.error_level = min(state.error_level, vote)

			if diff_regex.flags & re.MULTILINE:
				text = file_info.contents
				for m in diff_regex.finditer(file_info.contents):
					start_line_num = first_line_num + text.count('\n', 0, m.start())
					matching_text = text[m.start():m.end()]
					suggestion = self.suggester.get_suggestion(matching_text, rule)
					self.logger.log(log_level, "%s (%d): \"%s\" matches '%s'.%s%s", path, start_line_num, text[m.start():m.end()], diff_regex.pattern, comment, suggestion)
					state.error_level = min(state.error_level, vote)



def main():
	import argparse

	from injector import Injector

	from config import ConfigModule
	from logger import LoggingModule
	from suggestions import SuggesterModule

	parser = argparse.ArgumentParser(
		prog="Code Reviewer",
		description="Review local files using regular expressions and other simple checks.",
	)
	parser.add_argument(
		'--config_source',
		type=str,
		required=True,
		help="(required) Path to the configuration file.",
	)
	parser.add_argument(
		'paths',
		nargs='+',
		help="(required) The files or folders to review."
	)
	parser.add_argument(
		'--severity',
		type=str,
		default='REJECT',
		help="Minimum severity level to exit with an error.",
		# TODO Make better name for the no vote.
		choices=('none', 'wait', 'REJECT'),
	)
	parser.add_argument(
		'--fix',
		action='store_true',
		help="(not supported yet) Automatically fix issues."
	)

	args = parser.parse_args()
	config_source: str = args.config_source

	inj = Injector([
		ConfigModule(config_source),
		LoggingModule,
		SuggesterModule,
	])
	options = RunOptions(args.paths, args.severity, args.fix)
	runner = inj.get(LocalReviewer)
	runner.run(options)


if __name__ == '__main__':
	main()
