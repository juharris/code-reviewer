import logging
import sys
from dataclasses import dataclass

from injector import inject

from config import Config, ConfigLoader, JsonPathCheck, MatchType, Rule
from suggestions import Suggester


@inject
@dataclass
class LocalReviewer:
	config: Config
	logger: logging.Logger
	suggester: Suggester

	def run(self):
		print(self.config)
		# TODO Loop over local files in the desired folders or names.



def main():
	from injector import Injector

	from config import ConfigModule
	from logger import LoggingModule
	from suggestions import SuggesterModule

	config_source = sys.argv[1]

	# TODO Parse args.
	# * Files/Folders
	# Allow passing file name or use a directory and recurse.
	# * Severity
	# Accept a severity argument for the minimum level at which to exit(1).
	# * --fix
	# Modify the file if a suggestion is generated.
 
	inj = Injector([
		ConfigModule(config_source),
		LoggingModule,
		SuggesterModule,
	])
	runner = inj.get(LocalReviewer)
	runner.run()


if __name__ == '__main__':
	main()
