# TODO Use injector
# from injector import Module

import logging


class LoggingModule:
	def provide_logger(self) -> logging.Logger:
		result = logging.getLogger(__name__)
		result.setLevel(logging.INFO)
		f = logging.Formatter('%(asctime)s [%(levelname)s] - %(name)s:%(filename)s:%(funcName)s\n%(message)s')
		h = logging.StreamHandler()
		h.setFormatter(f)
		result.addHandler(h)
		return result