from dataclasses import dataclass

from injector import ClassAssistedBuilder, Module, provider, singleton

from .config import Config
from .loader import ConfigLoader


@dataclass
class ConfigModule(Module):
    config_source: str

    @provider
    @singleton
    def provide_config_loader(self, builder: ClassAssistedBuilder[ConfigLoader]) -> ConfigLoader:
        return builder.build(config_source=self.config_source)

    @provider
    @singleton
    def provide_config(self, loader: ConfigLoader) -> Config:
        return loader.load_config().config
