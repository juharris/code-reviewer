import logging
import os
import re
from dataclasses import dataclass
from typing import Collection, Iterable, Optional

from injector import inject
from tqdm import tqdm

from config import Config, Rule
from local_run_state import LocalReviewRunState
from suggestions import Suggester
from voting import map_vote_to_log_level


@dataclass
class FileInfo:
	path: str
	contents: Optional[str] = None


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

	def run(self, paths: Collection[str]) -> None:
		paths = self.get_files(paths)
		state = LocalReviewRunState()
		for path in tqdm(paths,
			desc="Reviewing files",
			unit_scale=True, mininterval=2, unit=" files"
		):
			self.review_file(state, path)
		# TODO Exit depending on the severity level and `state.error_level``.


	def run_rule_for_file(self, state: LocalReviewRunState, file_info: FileInfo, rule: Rule) -> None:
		p = rule.get('path_regex')
		path = file_info.path
		if p is not None and not p.match(path):
			return
		diff_regex = rule.get('diff_regex')
		vote = rule.get('vote', 0)
		assert isinstance(vote, int), f"Expected vote to be an int. Got: {vote}"
		log_level = map_vote_to_log_level(vote)
		if diff_regex is not None:
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

			for line_num, line in enumerate(file_info.contents.splitlines(), start=1):
				line = line.rstrip('\r\n')
				# TODO If the regex is multiline, we need to use finditer.
				if diff_regex.match(line):
					# TODO Check vote to determine the log level.
					self.logger.log(log_level, "%s (%d): \"%s\" matches '%s'.%s", path, line_num, line, diff_regex.pattern, comment)
					state.error_level = max(state.error_level, log_level)

			if diff_regex.flags & re.MULTILINE:
				first_line_num = 1
				text = file_info.contents
				# TODO Check vote to determine the log level.
				for m in diff_regex.finditer(file_info.contents):
					start_line_num = first_line_num + text.count('\n', 0, m.start())
					start_offset = m.start() - text.rfind('\n', 0, m.start())
					end_line_num = start_line_num + text.count('\n', m.start(), m.end())
					end_offset = m.end() - text.rfind('\n', 0, m.end())
					self.logger.log(log_level, "%s (%d): \"%s\" matches '%s'.%s", path, start_line_num, text[m.start():m.end()], diff_regex.pattern, comment)
					state.error_level = max(state.error_level, log_level)



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
		help="Automatically fix issues."
	)

	args = parser.parse_args()
	config_source: str = args.config_source

	inj = Injector([
		ConfigModule(config_source),
		LoggingModule,
		SuggesterModule,
	])
	runner = inj.get(LocalReviewer)
	runner.run(args.paths)


if __name__ == '__main__':
	main()
