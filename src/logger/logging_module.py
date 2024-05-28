import logging
from logging import Logger

from injector import Module, provider, singleton

# Adapted from https://stackoverflow.com/a/56944256/782170


class CustomFormatter(logging.Formatter):
    blue = "\x1b[34;20m"
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_style = '%(asctime)s [%(levelname)s] - %(name)s:%(filename)s:%(funcName)s\n%(message)s'

    FORMATS = {
        logging.DEBUG: blue + format_style + reset,
        # logging.INFO: grey + format_style + reset,
        logging.WARNING: yellow + format_style + reset,
        logging.ERROR: red + format_style + reset,
        logging.CRITICAL: bold_red + format_style + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, CustomFormatter.format_style)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class LoggingModule(Module):
    @provider
    @singleton
    def provide_logger(self) -> Logger:
        result = logging.Logger('code-reviewer')
        result.setLevel(logging.INFO)
        h = logging.StreamHandler()
        h.setFormatter(CustomFormatter())
        result.addHandler(h)
        return result
