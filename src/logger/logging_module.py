import logging
from logging import Logger

from injector import Module, provider, singleton


class LoggingModule(Module):
	@provider
	@singleton
	def provide_logger(self) -> Logger:
		result = logging.Logger('code-reviewer')
		result.setLevel(logging.INFO)
		f = logging.Formatter('%(asctime)s [%(levelname)s] - %(name)s:%(filename)s:%(funcName)s\n%(message)s')
		h = logging.StreamHandler()
		h.setFormatter(f)
		result.addHandler(h)
		return result