"""Cloud API clients for live-mode scanning.

Each client module lazily imports its heavy SDK dependency (boto3,
google-cloud-resourcemanager, azure-*) inside the function body, so users who
only want offline JSON auditing never have to install them. When the SDK is
missing or credentials aren't available, a `CloudClientError` is raised with
an actionable message (e.g. "Run `pip install cloud-iam-auditor-pb[live]`").
"""

from .errors import CloudClientError, MissingDependencyError, NoCredentialsError

__all__ = ["CloudClientError", "MissingDependencyError", "NoCredentialsError"]
