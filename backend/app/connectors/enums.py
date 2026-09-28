"""Provider-agnostic vocabularies shared by every connector."""
from __future__ import annotations

from enum import StrEnum


class ConnectorProvider(StrEnum):
    """Registry key. Only GITHUB has a real connector today - the rest exist so
    the enum, and anything that switches on it, does not need to change shape
    when the next provider is implemented."""
    GITHUB = "github"
    GMAIL = "gmail"
    GOOGLE_DRIVE = "google_drive"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    SLACK = "slack"
    JIRA = "jira"
    DISCORD = "discord"
    LINEAR = "linear"
    AZURE_DEVOPS = "azure_devops"
    NOTION = "notion"


class ConnectorStatus(StrEnum):
    """Health of one connector_installations row."""
    HEALTHY = "healthy"
    SYNCING = "syncing"
    EXPIRED = "expired"
    DISCONNECTED = "disconnected"
    PERMISSION_LOST = "permission_lost"
    WEBHOOK_FAILED = "webhook_failed"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class MonitoringStatus(StrEnum):
    """Per-resource (repository, channel, doc, ...) monitoring state."""
    MONITORED = "monitored"
    MANUAL_ONLY = "manual_only"
    ARCHIVED = "archived"
    PERMISSION_LOST = "permission_lost"
    DISABLED = "disabled"


class LifecycleEvent(StrEnum):
    """Provider-agnostic SSE events every connector emits the same way."""
    INSTALLATION_CREATED = "connector.installation.created"
    INSTALLATION_UPDATED = "connector.installation.updated"
    INSTALLATION_DELETED = "connector.installation.deleted"
    RESOURCE_ADDED = "connector.resource.added"
    RESOURCE_UPDATED = "connector.resource.updated"
    RESOURCE_REMOVED = "connector.resource.removed"
    CONNECTED = "connector.connected"
    DISCONNECTED = "connector.disconnected"
    SYNC_STARTED = "connector.sync.started"
    SYNC_PROGRESS = "connector.sync.progress"
    SYNC_COMPLETED = "connector.sync.completed"
    SYNC_FAILED = "connector.sync.failed"
