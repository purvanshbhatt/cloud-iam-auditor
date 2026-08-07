"""Exceptions used by the cloud_client layer."""

from __future__ import annotations

INSTALL_HINT_LIVE = "pip install cloud-iam-auditor-pb[live]"
INSTALL_HINT_AZURE = "pip install cloud-iam-auditor-pb[azure]"


class CloudClientError(Exception):
    """Base class for any live-mode API client failure."""


class MissingDependencyError(CloudClientError):
    """Raised when an optional SDK is needed but not installed."""

    @classmethod
    def for_live(cls, dep_name: str) -> MissingDependencyError:
        return cls(
            f"The '{dep_name}' package is required for live AWS/GCP scanning "
            f"but is not installed. Install it via:\n\n  {INSTALL_HINT_LIVE}\n"
        )

    @classmethod
    def for_azure(cls, dep_name: str) -> MissingDependencyError:
        return cls(
            f"The '{dep_name}' package is required for live Azure scanning "
            f"but is not installed. Install it via:\n\n  {INSTALL_HINT_AZURE}\n"
        )


class NoCredentialsError(CloudClientError):
    """Raised when the cloud SDK can't locate any credentials for the call."""

    @classmethod
    def for_aws(cls, hint: str = "") -> NoCredentialsError:
        base = (
            "boto3 could not locate AWS credentials. Configure the default "
            "credential chain (env vars AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, "
            "~/.aws/credentials profile, instance role, or SSO)."
        )
        if hint:
            base = f"{base} Detail: {hint}"
        base = (
            f"{base} If the boto3 SDK is missing entirely, install via: "
            f"{INSTALL_HINT_LIVE}"
        )
        return cls(base)

    @classmethod
    def for_gcp(cls, hint: str = "") -> NoCredentialsError:
        base = (
            "google-auth could not locate GCP credentials. Set "
            "GOOGLE_APPLICATION_CREDENTIALS to a service-account key file, or run "
            "`gcloud auth application-default login`."
        )
        if hint:
            base = f"{base} Detail: {hint}"
        base = (
            f"{base} If the google-cloud SDK is missing entirely, install via: "
            f"{INSTALL_HINT_LIVE}"
        )
        return cls(base)

    @classmethod
    def for_azure(cls, hint: str = "") -> NoCredentialsError:
        base = (
            "azure-identity could not locate Azure credentials. Set AZURE_TENANT_ID, "
            "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars, or run `az login`."
        )
        if hint:
            base = f"{base} Detail: {hint}"
        base = (
            f"{base} If the azure SDK is missing entirely, install via: "
            f"{INSTALL_HINT_AZURE}"
        )
        return cls(base)


class ApiCallError(CloudClientError):
    """Raised when an API call fails after authentication (e.g. permission error)."""
