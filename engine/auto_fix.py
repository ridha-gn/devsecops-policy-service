"""
Auto-Fix Engine — Generates corrected infrastructure code.

For each known violation, applies a rule-based text transformation
to produce secure code. Returns the fixed code + a list of changes.
"""

import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class FixApplied:
    rule_id: str
    line_number: Optional[int]
    description: str
    original: str
    fixed: str


@dataclass
class FixResult:
    original_code: str
    fixed_code: str
    fixes_applied: List[FixApplied] = field(default_factory=list)
    total_fixes: int = 0

    @property
    def has_fixes(self) -> bool:
        return self.total_fixes > 0


# ──────────────────────────────────────────────────────────────────────
#  TERRAFORM FIXES
# ──────────────────────────────────────────────────────────────────────

def _fix_public_s3_acl(code: str, fixes: List[FixApplied]) -> str:
    """Fix PUBLIC_S3_BUCKET: change public ACL to private."""
    pattern = r'(acl\s*=\s*["\'])(public-read-write|public-read)(["\'])'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="PUBLIC_S3_BUCKET",
            line_number=code[:m.start()].count('\n') + 1,
            description=f"Changed ACL from '{m.group(2)}' to 'private'",
            original=m.group(0),
            fixed=f'{m.group(1)}private{m.group(3)}'
        ))
    return re.sub(pattern, r'\1private\3', code)


def _fix_public_database(code: str, fixes: List[FixApplied]) -> str:
    """Fix PUBLIC_DATABASE: set publicly_accessible to false."""
    pattern = r'(publicly_accessible\s*=\s*)true'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="PUBLIC_DATABASE",
            line_number=code[:m.start()].count('\n') + 1,
            description="Set publicly_accessible to false",
            original=m.group(0),
            fixed=f'{m.group(1)}false'
        ))
    return re.sub(pattern, r'\1false', code)


def _fix_unencrypted_storage(code: str, fixes: List[FixApplied]) -> str:
    """Fix UNENCRYPTED_STORAGE: set storage_encrypted to true."""
    pattern = r'(storage_encrypted\s*=\s*)false'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="UNENCRYPTED_STORAGE",
            line_number=code[:m.start()].count('\n') + 1,
            description="Enabled storage encryption",
            original=m.group(0),
            fixed=f'{m.group(1)}true'
        ))
    return re.sub(pattern, r'\1true', code)


def _fix_hardcoded_secrets(code: str, fixes: List[FixApplied]) -> str:
    """Fix HARDCODED_SECRET: replace credentials with variable references."""
    # AWS Access Keys
    ak_pattern = r'(access_key\s*=\s*["\'])AKIA[0-9A-Z]{16}(["\'])'
    matches = list(re.finditer(ak_pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="HARDCODED_SECRET",
            line_number=code[:m.start()].count('\n') + 1,
            description="Replaced hardcoded AWS access key with variable reference",
            original=m.group(0),
            fixed=f'{m.group(1)}${{var.aws_access_key}}{m.group(2)}'
        ))
    code = re.sub(ak_pattern, r'\1${var.aws_access_key}\2', code)

    # Password fields
    pw_pattern = r'(password\s*=\s*["\'])[^"\']+(["\'])'
    matches = list(re.finditer(pw_pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="HARDCODED_SECRET",
            line_number=code[:m.start()].count('\n') + 1,
            description="Replaced hardcoded password with variable reference",
            original=m.group(0),
            fixed=f'{m.group(1)}${{var.db_password}}{m.group(2)}'
        ))
    code = re.sub(pw_pattern, r'\1${var.db_password}\2', code)

    # Secret key fields
    sk_pattern = r'(secret_key\s*=\s*["\'])[^"\']+(["\'])'
    matches = list(re.finditer(sk_pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="HARDCODED_SECRET",
            line_number=code[:m.start()].count('\n') + 1,
            description="Replaced hardcoded secret key with variable reference",
            original=m.group(0),
            fixed=f'{m.group(1)}${{var.aws_secret_key}}{m.group(2)}'
        ))
    code = re.sub(sk_pattern, r'\1${var.aws_secret_key}\2', code)

    return code


def _fix_security_group(code: str, fixes: List[FixApplied]) -> str:
    """Fix INSECURE_SECURITY_GROUP: restrict 0.0.0.0/0 to specific range."""
    pattern = r'(cidr_blocks\s*=\s*\[[\s]*["\'])0\.0\.0\.0/0(["\'])'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="INSECURE_SECURITY_GROUP",
            line_number=code[:m.start()].count('\n') + 1,
            description="Restricted CIDR from 0.0.0.0/0 to 10.0.0.0/8 (private range)",
            original=m.group(0),
            fixed=f'{m.group(1)}10.0.0.0/8{m.group(2)}'
        ))
    return re.sub(pattern, r'\g<1>10.0.0.0/8\2', code)


def _fix_ec2_imdsv1(code: str, fixes: List[FixApplied]) -> str:
    """Fix EC2_IMDSV1: add metadata_options with http_tokens = required."""
    # Find instances without metadata_options
    instance_pattern = r'(resource\s+"aws_instance"\s+"[^"]+"\s*\{)'
    matches = list(re.finditer(instance_pattern, code))
    for m in matches:
        # Check if metadata_options already exists after this resource
        block_after = code[m.end():]
        if 'metadata_options' not in block_after.split('}')[0]:
            insert = '\n  metadata_options {\n    http_tokens = "required"\n  }\n'
            fixes.append(FixApplied(
                rule_id="EC2_IMDSV1_ENABLED",
                line_number=code[:m.start()].count('\n') + 1,
                description="Added metadata_options with http_tokens = required (IMDSv2)",
                original="(missing metadata_options block)",
                fixed="metadata_options { http_tokens = \"required\" }"
            ))
            code = code[:m.end()] + insert + code[m.end():]
    return code


def _fix_ec2_public_ip(code: str, fixes: List[FixApplied]) -> str:
    """Fix EC2_PUBLIC_IP: set associate_public_ip_address to false."""
    pattern = r'(associate_public_ip_address\s*=\s*)true'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="EC2_PUBLIC_IP_ASSIGNED",
            line_number=code[:m.start()].count('\n') + 1,
            description="Disabled automatic public IP assignment",
            original=m.group(0),
            fixed=f'{m.group(1)}false'
        ))
    return re.sub(pattern, r'\1false', code)


def _fix_rds_deletion_protection(code: str, fixes: List[FixApplied]) -> str:
    """Fix RDS_DELETION_PROTECTION: set deletion_protection to true."""
    pattern = r'(deletion_protection\s*=\s*)false'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="RDS_DELETION_PROTECTION_DISABLED",
            line_number=code[:m.start()].count('\n') + 1,
            description="Enabled deletion protection",
            original=m.group(0),
            fixed=f'{m.group(1)}true'
        ))
    return re.sub(pattern, r'\1true', code)


# ──────────────────────────────────────────────────────────────────────
#  DOCKERFILE FIXES
# ──────────────────────────────────────────────────────────────────────

def _fix_docker_root_user(code: str, fixes: List[FixApplied]) -> str:
    """Fix DOCKER_ROOT_USER: add USER instruction before CMD/ENTRYPOINT."""
    lines = code.split('\n')
    has_user = any(line.strip().startswith('USER') and
                   line.strip().split()[1:] and
                   line.strip().split()[1].lower() not in ['root', '0']
                   for line in lines if line.strip().startswith('USER'))

    if not has_user:
        # Find CMD or ENTRYPOINT line and insert USER before it
        for i, line in enumerate(lines):
            stripped = line.strip().upper()
            if stripped.startswith('CMD') or stripped.startswith('ENTRYPOINT'):
                lines.insert(i, 'USER appuser')
                lines.insert(i, 'RUN useradd -m -u 1000 appuser')
                fixes.append(FixApplied(
                    rule_id="DOCKER_ROOT_USER",
                    line_number=i + 1,
                    description="Added non-root user 'appuser' before CMD",
                    original="(no USER instruction)",
                    fixed="RUN useradd -m -u 1000 appuser\nUSER appuser"
                ))
                return '\n'.join(lines)

        # No CMD/ENTRYPOINT found — append at end
        lines.append('RUN useradd -m -u 1000 appuser')
        lines.append('USER appuser')
        fixes.append(FixApplied(
            rule_id="DOCKER_ROOT_USER",
            line_number=len(lines),
            description="Added non-root user 'appuser' at end of Dockerfile",
            original="(no USER instruction)",
            fixed="RUN useradd -m -u 1000 appuser\nUSER appuser"
        ))

    return '\n'.join(lines)


def _fix_docker_latest_tag(code: str, fixes: List[FixApplied]) -> str:
    """Fix DOCKER_LATEST_TAG: replace :latest with a specific version tag."""
    pattern = r'(FROM\s+\S+):latest'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="DOCKER_LATEST_TAG",
            line_number=code[:m.start()].count('\n') + 1,
            description="Replaced ':latest' tag — pin to a specific version",
            original=m.group(0),
            fixed=f'{m.group(1)}:<PIN_VERSION>'
        ))
    code = re.sub(pattern, r'\1:<PIN_VERSION>', code)

    # Also fix FROM without any tag
    pattern2 = r'(FROM\s+)([\w\-\.]+)(\s)'
    matches2 = list(re.finditer(pattern2, code))
    for m in matches2:
        if ':' not in m.group(2):
            fixes.append(FixApplied(
                rule_id="DOCKER_LATEST_TAG",
                line_number=code[:m.start()].count('\n') + 1,
                description=f"Image '{m.group(2)}' has no version tag — added placeholder",
                original=m.group(0).strip(),
                fixed=f'{m.group(1)}{m.group(2)}:<PIN_VERSION>'
            ))
    code = re.sub(pattern2, lambda m: f'{m.group(1)}{m.group(2)}:<PIN_VERSION>{m.group(3)}'
                  if ':' not in m.group(2) else m.group(0), code)

    return code


def _fix_docker_healthcheck(code: str, fixes: List[FixApplied]) -> str:
    """Fix DOCKER_NO_HEALTHCHECK: add HEALTHCHECK instruction."""
    if 'HEALTHCHECK' not in code.upper():
        lines = code.split('\n')
        # Insert before CMD/ENTRYPOINT
        for i, line in enumerate(lines):
            stripped = line.strip().upper()
            if stripped.startswith('CMD') or stripped.startswith('ENTRYPOINT'):
                hc = 'HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost:8080/ || exit 1'
                lines.insert(i, hc)
                lines.insert(i, '')
                fixes.append(FixApplied(
                    rule_id="DOCKER_NO_HEALTHCHECK",
                    line_number=i + 1,
                    description="Added HEALTHCHECK instruction",
                    original="(no HEALTHCHECK)",
                    fixed=hc
                ))
                return '\n'.join(lines)
    return code


# ──────────────────────────────────────────────────────────────────────
#  KUBERNETES FIXES
# ──────────────────────────────────────────────────────────────────────

def _fix_k8s_privileged(code: str, fixes: List[FixApplied]) -> str:
    """Fix PRIVILEGED_CONTAINER: change privileged: true to false."""
    pattern = r'(privileged:\s*)true'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="PRIVILEGED_CONTAINER",
            line_number=code[:m.start()].count('\n') + 1,
            description="Disabled privileged mode",
            original=m.group(0),
            fixed=f'{m.group(1)}false'
        ))
    return re.sub(pattern, r'\1false', code)


def _fix_k8s_host_network(code: str, fixes: List[FixApplied]) -> str:
    """Fix HOST_NETWORK_ENABLED: change hostNetwork: true to false."""
    pattern = r'(hostNetwork:\s*)true'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="HOST_NETWORK_ENABLED",
            line_number=code[:m.start()].count('\n') + 1,
            description="Disabled host network mode",
            original=m.group(0),
            fixed=f'{m.group(1)}false'
        ))
    return re.sub(pattern, r'\1false', code)


def _fix_k8s_privilege_escalation(code: str, fixes: List[FixApplied]) -> str:
    """Fix K8S_ALLOW_PRIVILEGE_ESCALATION: set to false."""
    pattern = r'(allowPrivilegeEscalation:\s*)true'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="K8S_ALLOW_PRIVILEGE_ESCALATION",
            line_number=code[:m.start()].count('\n') + 1,
            description="Disabled privilege escalation",
            original=m.group(0),
            fixed=f'{m.group(1)}false'
        ))
    return re.sub(pattern, r'\1false', code)


def _fix_k8s_run_as_root(code: str, fixes: List[FixApplied]) -> str:
    """Fix K8S_RUN_AS_ROOT: change runAsUser: 0 to 1000."""
    pattern = r'(runAsUser:\s*)0(\s)'
    matches = list(re.finditer(pattern, code))
    for m in matches:
        fixes.append(FixApplied(
            rule_id="K8S_RUN_AS_ROOT",
            line_number=code[:m.start()].count('\n') + 1,
            description="Changed runAsUser from 0 (root) to 1000",
            original=m.group(0).strip(),
            fixed=f'{m.group(1)}1000'
        ))
    return re.sub(pattern, r'\g<1>1000\2', code)


# ──────────────────────────────────────────────────────────────────────
#  MAIN AUTO-FIX CLASS
# ──────────────────────────────────────────────────────────────────────

TERRAFORM_FIXERS = [
    _fix_public_s3_acl,
    _fix_public_database,
    _fix_unencrypted_storage,
    _fix_hardcoded_secrets,
    _fix_security_group,
    _fix_ec2_imdsv1,
    _fix_ec2_public_ip,
    _fix_rds_deletion_protection,
]

DOCKERFILE_FIXERS = [
    _fix_docker_root_user,
    _fix_docker_latest_tag,
    _fix_docker_healthcheck,
]

KUBERNETES_FIXERS = [
    _fix_k8s_privileged,
    _fix_k8s_host_network,
    _fix_k8s_privilege_escalation,
    _fix_k8s_run_as_root,
]


class AutoFixer:
    """Applies rule-based fixes to infrastructure code."""

    def fix(self, code_type: str, content: str) -> FixResult:
        fixes: List[FixApplied] = []
        fixed_code = content

        if code_type == "terraform":
            fixers = TERRAFORM_FIXERS
        elif code_type == "dockerfile":
            fixers = DOCKERFILE_FIXERS
        elif code_type == "yaml":
            fixers = KUBERNETES_FIXERS
        else:
            return FixResult(
                original_code=content,
                fixed_code=content,
                fixes_applied=[],
                total_fixes=0
            )

        for fixer_fn in fixers:
            fixed_code = fixer_fn(fixed_code, fixes)

        return FixResult(
            original_code=content,
            fixed_code=fixed_code,
            fixes_applied=fixes,
            total_fixes=len(fixes)
        )

    def generate_diff(self, original: str, fixed: str) -> str:
        """Generate a simple unified-style diff between original and fixed."""
        orig_lines = original.splitlines()
        fixed_lines = fixed.splitlines()
        diff_lines = []

        import difflib
        for line in difflib.unified_diff(
            orig_lines, fixed_lines,
            fromfile='original', tofile='fixed',
            lineterm=''
        ):
            diff_lines.append(line)

        return '\n'.join(diff_lines)
