import logging
import os
from dataclasses import dataclass
from typing import Collection, Iterable

from injector import inject
from tqdm import tqdm

from config import Config, Rule
from suggestions import Suggester


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

	def review_file(self, path: str):
		rules = self.config.get('rules')
		assert rules is not None
		for rule in rules:
			self.run_rule_for_file(path, rule)
			
	def run(self, paths: Collection[str]) -> None:
		paths = self.get_files(paths)
		for path in tqdm(paths,
			desc="Reviewing files",
			unit_scale=True, mininterval=2, unit=" files"
		):
			self.review_file(path)

		
	def run_rule_for_file(self, path: str, rule: Rule):
		# TODO
		pass


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
