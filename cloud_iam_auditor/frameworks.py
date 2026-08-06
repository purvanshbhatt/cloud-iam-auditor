"""Authoritative framework mapping registry (NIST 800-53, NIST 800-207, CIS AWS Foundations, MITRE ATT&CK).

Each constant here maps a stable alias -> human-readable reference string used
in both the Rich table and the JSON report. Rules reference these aliases only;
the actual framework prose lives here so it can be audited/updated centrally.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkRef:
    alias: str
    framework: str
    identifier: str
    description: str

    def render(self) -> str:
        return f"{self.framework} {self.identifier} - {self.description}"


_REGISTRY: dict[str, FrameworkRef] = {
    # NIST SP 800-53 Rev. 5
    "NIST_AC_6": FrameworkRef(
        "NIST_AC_6", "NIST 800-53", "AC-6",
        "Least Privilege",
    ),
    "NIST_AC_6_5": FrameworkRef(
        "NIST_AC_6_5", "NIST 800-53", "AC-6(5)",
        "Privileged Accounts",
    ),
    "NIST_AC_6_7": FrameworkRef(
        "NIST_AC_6_7", "NIST 800-53", "AC-6(7)",
        "Review of User Privileges",
    ),
    "NIST_AC_3": FrameworkRef(
        "NIST_AC_3", "NIST 800-53", "AC-3",
        "Access Enforcement",
    ),
    "NIST_SC_12": FrameworkRef(
        "NIST_SC_12", "NIST 800-53", "SC-12",
        "Cryptographic Key Establishment and Management",
    ),
    "NIST_SC_28": FrameworkRef(
        "NIST_SC_28", "NIST 800-53", "SC-28",
        "Protection of Information at Rest",
    ),
    "NIST_IA_2": FrameworkRef(
        "NIST_IA_2", "NIST 800-53", "IA-2",
        "Identification and Authentication (Organizational Users)",
    ),
    "NIST_IA_2_1": FrameworkRef(
        "NIST_IA_2_1", "NIST 800-53", "IA-2(1)",
        "Multi-Factor Authentication to Privileged Accounts",
    ),
    # NIST SP 800-207 (Zero Trust Architecture)
    "ZT_3": FrameworkRef(
        "ZT_3", "NIST 800-207", "3",
        "Permitted resources and actions are read from a policy engine/decision point",
    ),
    "ZT_3_2_1": FrameworkRef(
        "ZT_3_2_1", "NIST 800-207", "3.2.1",
        "Resource actions must be dynamic and constantly evaluated",
    ),
    # CIS Amazon Web Services Foundations Benchmark v3.0
    "CIS_1_16": FrameworkRef(
        "CIS_1_16", "CIS AWS Foundations", "1.16",
        "Ensure IAM policies that allow full '*:* administrative privileges are not created",
    ),
    "CIS_1_4": FrameworkRef(
        "CIS_1_4", "CIS AWS Foundations", "1.4",
        "Ensure access keys are rotated every 90 days or less",
    ),
    "CIS_2_1_5": FrameworkRef(
        "CIS_2_1_5", "CIS AWS Foundations", "2.1.5",
        "Ensure S3 bucket policy does not allow write access to everyone",
    ),
    "CIS_2_8": FrameworkRef(
        "CIS_2_8", "CIS AWS Foundations", "2.8",
        "Ensure KMS key policies are not overly permissive",
    ),
    # MITRE ATT&CK Enterprise techniques
    "MITRE_T1078": FrameworkRef(
        "MITRE_T1078", "MITRE ATT&CK", "T1078",
        "Valid Accounts",
    ),
    "MITRE_T1078_004": FrameworkRef(
        "MITRE_T1078_004", "MITRE ATT&CK", "T1078.004",
        "Valid Accounts: Cloud Accounts",
    ),
    "MITRE_T1098": FrameworkRef(
        "MITRE_T1098", "MITRE ATT&CK", "T1098",
        "Account Manipulation",
    ),
    "MITRE_T1556": FrameworkRef(
        "MITRE_T1556", "MITRE ATT&CK", "T1556",
        "Modify Authentication Process",
    ),
    "MITRE_T1550": FrameworkRef(
        "MITRE_T1550", "MITRE ATT&CK", "T1550",
        "Use Alternate Authentication Material",
    ),
    "MITRE_T1550_001": FrameworkRef(
        "MITRE_T1550_001", "MITRE ATT&CK", "T1550.001",
        "Use Alternate Authentication Material: Application Access Token",
    ),
    # ---- v0.2.0 additions: CIS GCP Foundations Benchmark v3.0 ----
    "CIS_GCP_1_3": FrameworkRef(
        "CIS_GCP_1_3", "CIS GCP Foundations", "1.3",
        "Ensure that there are no highly privileged or sensitive service accounts in the project",
    ),
    "CIS_GCP_1_4": FrameworkRef(
        "CIS_GCP_1_4", "CIS GCP Foundations", "1.4",
        "Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator role at the project level",
    ),
    "CIS_GCP_1_5": FrameworkRef(
        "CIS_GCP_1_5", "CIS GCP Foundations", "1.5",
        "Ensure that Service Account has no Client-Email matching a corporate email",
    ),
    "CIS_GCP_1_10": FrameworkRef(
        "CIS_GCP_1_10", "CIS GCP Foundations", "1.10",
        "Ensure that IAM users are not assigned Service Account Token Creator role at organization level",
    ),
}


def resolve(alias: str) -> FrameworkRef:
    """Look up a framework reference by its alias; KeyError on miss."""
    return _REGISTRY[alias]


def describe(aliases) -> str:
    """Return a comma-joined render of one or more framework references."""
    if isinstance(aliases, str):
        aliases = [aliases]
    return ", ".join(resolve(a).render() for a in aliases)
