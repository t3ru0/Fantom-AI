"""Dynamic connector registry.

Only GitHub registers a real implementation today. The registry itself has no
opinion about that - it is just a dict keyed by provider, and asking for a
provider nobody registered is a clear `LookupError`, not a stub class.
"""
from __future__ import annotations

from app.connectors.base import BaseConnector
from app.connectors.enums import ConnectorProvider


class ConnectorRegistry:
    def __init__(self) -> None:
        self._connectors: dict[ConnectorProvider, BaseConnector] = {}

    def register(self, connector: BaseConnector) -> None:
        self._connectors[connector.provider] = connector

    def get(self, provider: ConnectorProvider) -> BaseConnector:
        try:
            return self._connectors[provider]
        except KeyError:
            raise LookupError(f"no connector registered for provider '{provider}'") from None

    def is_registered(self, provider: ConnectorProvider) -> bool:
        return provider in self._connectors

    def providers(self) -> list[ConnectorProvider]:
        return list(self._connectors.keys())


registry = ConnectorRegistry()


def _bootstrap() -> None:
    """Registers every connector that actually has an implementation. Import
    is local to avoid a hard import-time dependency from the framework package
    onto any one provider package."""
    from app.connectors.github.service import GitHubConnector

    registry.register(GitHubConnector())


_bootstrap()
