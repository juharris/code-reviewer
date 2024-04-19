import logging
import sys
from dataclasses import dataclass

from config import Config, ConfigLoader, JsonPathCheck, MatchType, Rule
from suggestions import Suggester


@dataclass
class LocalReviewer:
	config_loader: ConfigLoader
	logger: logging.Logger
	suggester: Suggester

	def run(self):
		pass


def main():
	from logger import LoggingModule

	config_source = sys.argv[1]

	# TODO Parse args.
	# Allow passing file name or use a directory and recurse.
	# Accept a severity argument for the minimum level at which to exit(1).
 
	# TODO Use injector.
	logger = LoggingModule().provide_logger()
	config_loader = ConfigLoader(config_source, logger)
	suggester = Suggester()
	runner = LocalReviewer(config_loader, logger, suggester)
	runner.run()


if __name__ == '__main__':
	main()
