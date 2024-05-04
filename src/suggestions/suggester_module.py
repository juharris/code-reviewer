from injector import Module, singleton

from .suggester import Suggester


class SuggesterModule(Module):
    def configure(self, binder):
        binder.bind(Suggester, scope=singleton)
