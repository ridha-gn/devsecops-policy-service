import re
from typing import Optional, List
from models.code_structure import NormalizedCode, Resource
from models.decision import PolicyViolation, PolicySeverity


class BasePolicy:
    def __init__(self, rule_id: str, severity: PolicySeverity, description: str):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        raise NotImplementedError


# ==============================================================================
# EXISTING 12 POLICIES (unchanged)
# ==============================================================================

class PublicS3BucketPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="PUBLIC_S3_BUCKET",
            severity=PolicySeverity.HIGH,
            description="S3 buckets should not be publicly accessible"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        s3_buckets = code.find_resources_by_type("aws_s3_bucket")
        for bucket in s3_buckets:
            acl = bucket.get_attribute("acl", "private")
            if acl in ["public-read", "public-read-write"]:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"S3 bucket '{bucket.resource_name}' has public ACL: {acl}",
                    line_number=bucket.line_number,
                    resource_type=bucket.resource_type,
                    resource_name=bucket.resource_name,
                    recommendation="Change ACL to 'private' and use bucket policies for controlled access"
                ))
        return violations


class HardcodedSecretsPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="HARDCODED_SECRET",
            severity=PolicySeverity.CRITICAL,
            description="Code should not contain hardcoded secrets"
        )
        self.secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
            (r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']', "AWS Secret Key"),
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded Password"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "API Key"),
        ]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        for resource in code.resources:
            for key, value in resource.attributes.items():
                if isinstance(value, str):
                    for pattern, secret_type in self.secret_patterns:
                        if re.search(pattern, value, re.IGNORECASE):
                            violations.append(PolicyViolation(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                message=f"{secret_type} detected in {resource.resource_type}",
                                line_number=resource.line_number,
                                resource_type=resource.resource_type,
                                resource_name=resource.resource_name,
                                recommendation="Use environment variables or secret management services"
                            ))
        return violations


class UnencryptedStoragePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="UNENCRYPTED_STORAGE",
            severity=PolicySeverity.HIGH,
            description="Storage resources should be encrypted"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        s3_buckets = code.find_resources_by_type("aws_s3_bucket")
        for bucket in s3_buckets:
            encryption = bucket.get_attribute("server_side_encryption_configuration")
            if not encryption:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"S3 bucket '{bucket.resource_name}' does not have encryption enabled",
                    line_number=bucket.line_number,
                    resource_type=bucket.resource_type,
                    resource_name=bucket.resource_name,
                    recommendation="Enable server-side encryption with AES256 or KMS"
                ))
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            encrypted = db.get_attribute("storage_encrypted", False)
            if not encrypted:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' storage is not encrypted",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set storage_encrypted = true"
                ))
        return violations


class RootDockerUserPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_ROOT_USER",
            severity=PolicySeverity.MEDIUM,
            description="Docker containers should not run as root"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        user_instructions = [r for r in code.resources if r.resource_type == "docker_user"]
        has_non_root_user = False
        for user_inst in user_instructions:
            user = user_inst.get_attribute("args", "")
            if user and user.lower() not in ["root", "0"]:
                has_non_root_user = True
        if not has_non_root_user and len(code.resources) > 0:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message="Dockerfile does not specify a non-root USER",
                line_number=None,
                resource_type="dockerfile",
                resource_name="USER",
                recommendation="Add 'USER <non-root-user>' instruction before CMD/ENTRYPOINT"
            ))
        return violations


class MissingTagsPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="MISSING_REQUIRED_TAGS",
            severity=PolicySeverity.LOW,
            description="Resources should have required tags for compliance"
        )
        self.required_tags = ["Environment", "Owner", "CostCenter"]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        taggable_types = ["aws_s3_bucket", "aws_instance", "aws_db_instance"]
        for resource in code.resources:
            if resource.resource_type in taggable_types:
                tags = resource.get_attribute("tags", {})
                missing_tags = [tag for tag in self.required_tags if tag not in tags]
                if missing_tags:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Resource '{resource.resource_name}' missing tags: {', '.join(missing_tags)}",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation=f"Add tags: {', '.join(missing_tags)}"
                    ))
        return violations


class InsecureSecurityGroupPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="INSECURE_SECURITY_GROUP",
            severity=PolicySeverity.HIGH,
            description="Security groups should not allow unrestricted access"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        security_groups = code.find_resources_by_type("aws_security_group")
        for sg in security_groups:
            ingress_rules = sg.get_attribute("ingress", [])
            if not isinstance(ingress_rules, list):
                ingress_rules = [ingress_rules]
            for rule in ingress_rules:
                if isinstance(rule, dict):
                    cidr_blocks = rule.get("cidr_blocks", [])
                    if "0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks:
                        from_port = rule.get("from_port", 0)
                        to_port = rule.get("to_port", 0)
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Security group '{sg.resource_name}' allows unrestricted access (0.0.0.0/0) on ports {from_port}-{to_port}",
                            line_number=sg.line_number,
                            resource_type=sg.resource_type,
                            resource_name=sg.resource_name,
                            recommendation="Restrict access to specific IP ranges or use AWS security group references"
                        ))
        return violations


class MissingLoggingPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="MISSING_LOGGING",
            severity=PolicySeverity.MEDIUM,
            description="Resources should have logging enabled for audit trails"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        s3_buckets = code.find_resources_by_type("aws_s3_bucket")
        for bucket in s3_buckets:
            logging_config = bucket.get_attribute("logging")
            if not logging_config:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"S3 bucket '{bucket.resource_name}' does not have logging enabled",
                    line_number=bucket.line_number,
                    resource_type=bucket.resource_type,
                    resource_name=bucket.resource_name,
                    recommendation="Enable S3 bucket logging to track access requests"
                ))
        return violations


class PublicDatabasePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="PUBLIC_DATABASE",
            severity=PolicySeverity.CRITICAL,
            description="Databases should not be publicly accessible"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            publicly_accessible = db.get_attribute("publicly_accessible", False)
            if publicly_accessible:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' is publicly accessible",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set publicly_accessible = false and use VPN/bastion host for access"
                ))
        return violations


class ExpensiveInstancePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EXPENSIVE_INSTANCE_TYPE",
            severity=PolicySeverity.MEDIUM,
            description="Expensive instance types should be reviewed for cost optimization"
        )
        self.expensive_types = [
            "m5.8xlarge", "m5.12xlarge", "m5.16xlarge", "m5.24xlarge",
            "c5.9xlarge", "c5.12xlarge", "c5.18xlarge", "c5.24xlarge",
            "r5.8xlarge", "r5.12xlarge", "r5.16xlarge", "r5.24xlarge",
            "p3.8xlarge", "p3.16xlarge", "p3dn.24xlarge"
        ]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            instance_type = instance.get_attribute("instance_type", "")
            if instance_type in self.expensive_types:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Instance '{instance.resource_name}' uses expensive type: {instance_type}",
                    line_number=instance.line_number,
                    resource_type=instance.resource_type,
                    resource_name=instance.resource_name,
                    recommendation="Consider using smaller instance types or reserved instances for cost savings"
                ))
        return violations


class PrivilegedContainerPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="PRIVILEGED_CONTAINER",
            severity=PolicySeverity.HIGH,
            description="Containers should not run in privileged mode"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                privileged = resource.get_attribute("privileged", False)
                if privileged:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' is running in privileged mode",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Remove 'privileged: true' from securityContext. Use specific capabilities instead."
                    ))
        return violations


class HostNetworkPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="HOST_NETWORK_ENABLED",
            severity=PolicySeverity.MEDIUM,
            description="Pods should not use host network"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        host_network_resources = [r for r in code.resources if r.resource_type == "k8s_host_network"]
        for resource in host_network_resources:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message=f"Pod '{resource.resource_name}' uses host network",
                line_number=resource.line_number,
                resource_type=resource.resource_type,
                resource_name=resource.resource_name,
                recommendation="Set hostNetwork: false or remove the field. Use Services for network access."
            ))
        return violations


class MissingResourceLimitsPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="MISSING_RESOURCE_LIMITS",
            severity=PolicySeverity.LOW,
            description="Containers should define resource limits"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                resources_config = resource.get_attribute("resources", {})
                limits = resources_config.get("limits", {})
                if not limits or ("cpu" not in limits and "memory" not in limits):
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' has no resource limits defined",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Add resources.limits with cpu and memory values to prevent resource exhaustion"
                    ))
        return violations


# ==============================================================================
# NEW POLICIES — AWS S3 (13-20)
# ==============================================================================

class S3VersioningDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="S3_VERSIONING_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="S3 buckets should have versioning enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        s3_buckets = code.find_resources_by_type("aws_s3_bucket")
        for bucket in s3_buckets:
            versioning = bucket.get_attribute("versioning")
            if not versioning:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"S3 bucket '{bucket.resource_name}' does not have versioning enabled",
                    line_number=bucket.line_number,
                    resource_type=bucket.resource_type,
                    resource_name=bucket.resource_name,
                    recommendation="Enable versioning to protect against accidental deletion and data corruption"
                ))
            elif isinstance(versioning, dict) and not versioning.get("enabled", False):
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"S3 bucket '{bucket.resource_name}' has versioning explicitly disabled",
                    line_number=bucket.line_number,
                    resource_type=bucket.resource_type,
                    resource_name=bucket.resource_name,
                    recommendation="Set versioning { enabled = true }"
                ))
        return violations


class S3MFADeleteDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="S3_MFA_DELETE_DISABLED",
            severity=PolicySeverity.HIGH,
            description="S3 buckets should require MFA for deletion"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        s3_buckets = code.find_resources_by_type("aws_s3_bucket")
        for bucket in s3_buckets:
            versioning = bucket.get_attribute("versioning", {})
            if isinstance(versioning, dict):
                mfa_delete = versioning.get("mfa_delete", False)
                if not mfa_delete:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"S3 bucket '{bucket.resource_name}' does not require MFA for deletion",
                        line_number=bucket.line_number,
                        resource_type=bucket.resource_type,
                        resource_name=bucket.resource_name,
                        recommendation="Enable MFA delete in versioning configuration to prevent unauthorized deletion"
                    ))
        return violations


class S3TransferAccelerationPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="S3_LIFECYCLE_MISSING",
            severity=PolicySeverity.LOW,
            description="S3 buckets should have lifecycle policies for cost management"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        s3_buckets = code.find_resources_by_type("aws_s3_bucket")
        for bucket in s3_buckets:
            lifecycle = bucket.get_attribute("lifecycle_rule")
            acl = bucket.get_attribute("acl", "private")
            # Only flag if bucket is public (has real risk) and no lifecycle
            if acl in ["public-read", "public-read-write"] and not lifecycle:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"S3 bucket '{bucket.resource_name}' has no lifecycle policy defined",
                    line_number=bucket.line_number,
                    resource_type=bucket.resource_type,
                    resource_name=bucket.resource_name,
                    recommendation="Add lifecycle rules to transition old objects to cheaper storage tiers"
                ))
        return violations


class S3BlockPublicAclPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="S3_BLOCK_PUBLIC_ACL_MISSING",
            severity=PolicySeverity.MEDIUM,
            description="S3 buckets should block all public ACLs"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        s3_buckets = code.find_resources_by_type("aws_s3_bucket")
        for bucket in s3_buckets:
            block_public = bucket.get_attribute("block_public_acls", False)
            acl = bucket.get_attribute("acl", "private")
            # Only flag if bucket has public ACL but no block_public_acls protection
            if not block_public and acl in ["public-read", "public-read-write"]:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"S3 bucket '{bucket.resource_name}' is public but does not block public ACLs",
                    line_number=bucket.line_number,
                    resource_type=bucket.resource_type,
                    resource_name=bucket.resource_name,
                    recommendation="Set block_public_acls = true to prevent accidental public exposure"
                ))
        return violations


class S3CrossRegionReplicationPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="S3_REPLICATION_MISSING",
            severity=PolicySeverity.INFO,
            description="Critical S3 buckets should have cross-region replication"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        # Disabled — cross-region replication requires separate AWS config, too noisy for single-file scans
        return []


# ==============================================================================
# NEW POLICIES — AWS EC2 / COMPUTE (21-30)
# ==============================================================================

class EC2IMDSv1EnabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EC2_IMDSV1_ENABLED",
            severity=PolicySeverity.HIGH,
            description="EC2 instances should require IMDSv2 to prevent SSRF attacks"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            metadata = instance.get_attribute("metadata_options", {})
            http_tokens = metadata.get("http_tokens", "optional") if isinstance(metadata, dict) else "optional"
            if http_tokens != "required":
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EC2 instance '{instance.resource_name}' allows IMDSv1 (SSRF risk)",
                    line_number=instance.line_number,
                    resource_type=instance.resource_type,
                    resource_name=instance.resource_name,
                    recommendation="Set metadata_options { http_tokens = 'required' } to enforce IMDSv2"
                ))
        return violations


class EC2PublicIPAssignedPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EC2_PUBLIC_IP_ASSIGNED",
            severity=PolicySeverity.MEDIUM,
            description="EC2 instances should not have public IP addresses assigned automatically"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            public_ip = instance.get_attribute("associate_public_ip_address", False)
            if public_ip:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EC2 instance '{instance.resource_name}' automatically assigns a public IP",
                    line_number=instance.line_number,
                    resource_type=instance.resource_type,
                    resource_name=instance.resource_name,
                    recommendation="Set associate_public_ip_address = false and use a NAT gateway or bastion host"
                ))
        return violations


class EC2NoKeyPairPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EC2_NO_KEY_PAIR",
            severity=PolicySeverity.MEDIUM,
            description="EC2 instances should not use key pairs for SSH — use SSM instead"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            key_name = instance.get_attribute("key_name", "")
            if key_name:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EC2 instance '{instance.resource_name}' uses a key pair for SSH access",
                    line_number=instance.line_number,
                    resource_type=instance.resource_type,
                    resource_name=instance.resource_name,
                    recommendation="Use AWS Systems Manager Session Manager instead of SSH key pairs"
                ))
        return violations


class EC2EBSEncryptionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EC2_EBS_UNENCRYPTED",
            severity=PolicySeverity.HIGH,
            description="EBS volumes attached to EC2 instances should be encrypted"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            root_block = instance.get_attribute("root_block_device", {})
            if isinstance(root_block, dict) and not root_block.get("encrypted", False):
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EC2 instance '{instance.resource_name}' root EBS volume is not encrypted",
                    line_number=instance.line_number,
                    resource_type=instance.resource_type,
                    resource_name=instance.resource_name,
                    recommendation="Set root_block_device { encrypted = true }"
                ))
        ebs_volumes = code.find_resources_by_type("aws_ebs_volume")
        for vol in ebs_volumes:
            if not vol.get_attribute("encrypted", False):
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EBS volume '{vol.resource_name}' is not encrypted",
                    line_number=vol.line_number,
                    resource_type=vol.resource_type,
                    resource_name=vol.resource_name,
                    recommendation="Set encrypted = true on all EBS volumes"
                ))
        return violations


class EC2DetailedMonitoringPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EC2_DETAILED_MONITORING_DISABLED",
            severity=PolicySeverity.LOW,
            description="EC2 instances should have detailed monitoring enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            monitoring = instance.get_attribute("monitoring", False)
            if not monitoring:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EC2 instance '{instance.resource_name}' does not have detailed monitoring enabled",
                    line_number=instance.line_number,
                    resource_type=instance.resource_type,
                    resource_name=instance.resource_name,
                    recommendation="Set monitoring = true for better observability and incident response"
                ))
        return violations


class EC2TerminationProtectionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EC2_TERMINATION_PROTECTION_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="Production EC2 instances should have termination protection enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            tags = instance.get_attribute("tags", {})
            env = tags.get("Environment", "")
            disable_api_termination = instance.get_attribute("disable_api_termination", False)
            if env.lower() == "production" and not disable_api_termination:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Production EC2 instance '{instance.resource_name}' lacks termination protection",
                    line_number=instance.line_number,
                    resource_type=instance.resource_type,
                    resource_name=instance.resource_name,
                    recommendation="Set disable_api_termination = true for production instances"
                ))
        return violations


class EC2UserDataSecretsPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EC2_USERDATA_SECRETS",
            severity=PolicySeverity.CRITICAL,
            description="EC2 user_data should not contain hardcoded secrets"
        )
        self.secret_patterns = [
            r'password\s*=\s*\S+',
            r'secret\s*=\s*\S+',
            r'AKIA[0-9A-Z]{16}',
            r'api_key\s*=\s*\S+',
        ]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        instances = code.find_resources_by_type("aws_instance")
        for instance in instances:
            user_data = instance.get_attribute("user_data", "")
            if isinstance(user_data, str):
                for pattern in self.secret_patterns:
                    if re.search(pattern, user_data, re.IGNORECASE):
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"EC2 instance '{instance.resource_name}' has secrets in user_data",
                            line_number=instance.line_number,
                            resource_type=instance.resource_type,
                            resource_name=instance.resource_name,
                            recommendation="Use AWS Secrets Manager or Parameter Store instead of hardcoded values in user_data"
                        ))
                        break
        return violations


# ==============================================================================
# NEW POLICIES — AWS RDS / DATABASE (31-37)
# ==============================================================================

class RDSMultiAZDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="RDS_MULTI_AZ_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="Production RDS instances should have Multi-AZ enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            multi_az = db.get_attribute("multi_az", False)
            tags = db.get_attribute("tags", {})
            env = tags.get("Environment", "")
            if env.lower() == "production" and not multi_az:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Production RDS instance '{db.resource_name}' does not have Multi-AZ enabled",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set multi_az = true for high availability in production"
                ))
        return violations


class RDSBackupRetentionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="RDS_BACKUP_RETENTION_LOW",
            severity=PolicySeverity.MEDIUM,
            description="RDS instances should have adequate backup retention"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            retention = db.get_attribute("backup_retention_period", 0)
            if isinstance(retention, int) and retention < 7:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' backup retention is {retention} days (minimum 7 recommended)",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set backup_retention_period to at least 7 days"
                ))
        return violations


class RDSDeletionProtectionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="RDS_DELETION_PROTECTION_DISABLED",
            severity=PolicySeverity.HIGH,
            description="RDS instances should have deletion protection enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            deletion_protection = db.get_attribute("deletion_protection", False)
            if not deletion_protection:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' does not have deletion protection enabled",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set deletion_protection = true to prevent accidental database deletion"
                ))
        return violations


class RDSAutoMinorVersionUpgradePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="RDS_AUTO_MINOR_UPGRADE_DISABLED",
            severity=PolicySeverity.LOW,
            description="RDS instances should auto-apply minor version upgrades for security patches"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            auto_upgrade = db.get_attribute("auto_minor_version_upgrade", True)
            if not auto_upgrade:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' has auto minor version upgrade disabled",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set auto_minor_version_upgrade = true to receive security patches automatically"
                ))
        return violations


class RDSEnhancedMonitoringPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="RDS_ENHANCED_MONITORING_DISABLED",
            severity=PolicySeverity.LOW,
            description="RDS instances should have enhanced monitoring enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            monitoring_interval = db.get_attribute("monitoring_interval", 0)
            if monitoring_interval == 0:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' does not have enhanced monitoring enabled",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set monitoring_interval to 60 seconds and provide a monitoring_role_arn"
                ))
        return violations


class RDSPerformanceInsightsPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="RDS_PERFORMANCE_INSIGHTS_DISABLED",
            severity=PolicySeverity.LOW,
            description="RDS instances should have Performance Insights enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            perf_insights = db.get_attribute("performance_insights_enabled", False)
            if not perf_insights:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' does not have Performance Insights enabled",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation="Set performance_insights_enabled = true for query performance monitoring"
                ))
        return violations


class RDSDefaultPortPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="RDS_DEFAULT_PORT",
            severity=PolicySeverity.LOW,
            description="RDS instances should not use default database ports"
        )
        self.default_ports = {
            "mysql": 3306,
            "postgres": 5432,
            "oracle-ee": 1521,
            "sqlserver-ex": 1433,
        }

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        rds_instances = code.find_resources_by_type("aws_db_instance")
        for db in rds_instances:
            engine = db.get_attribute("engine", "")
            port = db.get_attribute("port", None)
            default_port = self.default_ports.get(engine)
            if default_port and (port is None or port == default_port):
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"RDS instance '{db.resource_name}' uses default port {default_port} for {engine}",
                    line_number=db.line_number,
                    resource_type=db.resource_type,
                    resource_name=db.resource_name,
                    recommendation=f"Change the database port from the default {default_port} to reduce attack surface"
                ))
        return violations


# ==============================================================================
# NEW POLICIES — AWS IAM (38-47)
# ==============================================================================

class IAMAdminPolicyAttachedPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="IAM_ADMIN_POLICY_ATTACHED",
            severity=PolicySeverity.CRITICAL,
            description="IAM roles and users should not have AdministratorAccess policy"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        for resource_type in ["aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"]:
            attachments = code.find_resources_by_type(resource_type)
            for attachment in attachments:
                policy_arn = attachment.get_attribute("policy_arn", "")
                if "AdministratorAccess" in str(policy_arn):
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Resource '{attachment.resource_name}' has AdministratorAccess policy attached",
                        line_number=attachment.line_number,
                        resource_type=attachment.resource_type,
                        resource_name=attachment.resource_name,
                        recommendation="Follow least-privilege principle. Attach only required permissions."
                    ))
        return violations


class IAMInlineAdminPolicyPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="IAM_INLINE_WILDCARD_POLICY",
            severity=PolicySeverity.CRITICAL,
            description="IAM inline policies should not use wildcard (*) actions on all resources"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        for resource_type in ["aws_iam_role_policy", "aws_iam_user_policy"]:
            policies = code.find_resources_by_type(resource_type)
            for policy in policies:
                policy_doc = str(policy.get_attribute("policy", ""))
                if '"Action": "*"' in policy_doc or '"Action":"*"' in policy_doc:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"IAM policy '{policy.resource_name}' uses wildcard Action on all resources",
                        line_number=policy.line_number,
                        resource_type=policy.resource_type,
                        resource_name=policy.resource_name,
                        recommendation="Specify exact actions needed instead of using wildcard '*'"
                    ))
        return violations


class IAMMFANotRequiredPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="IAM_MFA_NOT_REQUIRED",
            severity=PolicySeverity.HIGH,
            description="IAM users with console access should require MFA"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        iam_users = code.find_resources_by_type("aws_iam_user")
        for user in iam_users:
            force_destroy = user.get_attribute("force_destroy", False)
            tags = user.get_attribute("tags", {})
            mfa_enforced = tags.get("MFAEnforced", "false")
            if mfa_enforced.lower() != "true":
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"IAM user '{user.resource_name}' does not have MFA enforcement documented",
                    line_number=user.line_number,
                    resource_type=user.resource_type,
                    resource_name=user.resource_name,
                    recommendation="Enforce MFA via IAM policy condition and tag the user with MFAEnforced=true"
                ))
        return violations


class IAMAccessKeyRotationPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="IAM_ACCESS_KEY_NO_ROTATION",
            severity=PolicySeverity.MEDIUM,
            description="IAM access keys should have a rotation policy defined"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        access_keys = code.find_resources_by_type("aws_iam_access_key")
        for key in access_keys:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message=f"IAM access key '{key.resource_name}' is defined in Terraform — rotation cannot be automated",
                line_number=key.line_number,
                resource_type=key.resource_type,
                resource_name=key.resource_name,
                recommendation="Use IAM roles instead of long-lived access keys wherever possible"
            ))
        return violations


class IAMRoleWildcardTrustPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="IAM_ROLE_WILDCARD_TRUST",
            severity=PolicySeverity.CRITICAL,
            description="IAM roles should not trust all principals (*)"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        roles = code.find_resources_by_type("aws_iam_role")
        for role in roles:
            assume_role = str(role.get_attribute("assume_role_policy", ""))
            if '"Principal": "*"' in assume_role or '"Principal":"*"' in assume_role:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"IAM role '{role.resource_name}' trusts all principals (*)",
                    line_number=role.line_number,
                    resource_type=role.resource_type,
                    resource_name=role.resource_name,
                    recommendation="Restrict the trust policy to specific AWS services or accounts"
                ))
        return violations


class IAMPasswordPolicyPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="IAM_WEAK_PASSWORD_POLICY",
            severity=PolicySeverity.MEDIUM,
            description="IAM account password policy should enforce strong passwords"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        password_policies = code.find_resources_by_type("aws_iam_account_password_policy")
        for policy in password_policies:
            min_length = policy.get_attribute("minimum_password_length", 0)
            require_uppercase = policy.get_attribute("require_uppercase_characters", False)
            require_numbers = policy.get_attribute("require_numbers", False)
            require_symbols = policy.get_attribute("require_symbols", False)
            if min_length < 14 or not require_uppercase or not require_numbers or not require_symbols:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"IAM password policy '{policy.resource_name}' does not meet minimum security requirements",
                    line_number=policy.line_number,
                    resource_type=policy.resource_type,
                    resource_name=policy.resource_name,
                    recommendation="Set minimum_password_length=14, require uppercase, numbers, and symbols"
                ))
        return violations


class IAMGroupMembershipPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="IAM_USER_NO_GROUP",
            severity=PolicySeverity.LOW,
            description="IAM users should be assigned to groups for easier permission management"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        iam_users = code.find_resources_by_type("aws_iam_user")
        memberships = code.find_resources_by_type("aws_iam_user_group_membership")
        users_in_groups = set()
        for m in memberships:
            user = m.get_attribute("user", "")
            users_in_groups.add(user)
        for user in iam_users:
            if user.resource_name not in users_in_groups:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"IAM user '{user.resource_name}' is not assigned to any group",
                    line_number=user.line_number,
                    resource_type=user.resource_type,
                    resource_name=user.resource_name,
                    recommendation="Add the user to an IAM group and manage permissions at the group level"
                ))
        return violations


# ==============================================================================
# NEW POLICIES — AWS NETWORKING / VPC (48-55)
# ==============================================================================

class VPCFlowLogsDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="VPC_FLOW_LOGS_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="VPCs should have flow logs enabled for network monitoring"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        vpcs = code.find_resources_by_type("aws_vpc")
        flow_logs = code.find_resources_by_type("aws_flow_log")
        vpc_ids_with_logs = set()
        for log in flow_logs:
            vpc_id = log.get_attribute("vpc_id", "")
            vpc_ids_with_logs.add(vpc_id)
        for vpc in vpcs:
            if vpc.resource_name not in vpc_ids_with_logs:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"VPC '{vpc.resource_name}' does not have flow logs enabled",
                    line_number=vpc.line_number,
                    resource_type=vpc.resource_type,
                    resource_name=vpc.resource_name,
                    recommendation="Create an aws_flow_log resource targeting this VPC for network traffic analysis"
                ))
        return violations


class SecurityGroupSshOpenPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SECURITY_GROUP_SSH_OPEN",
            severity=PolicySeverity.HIGH,
            description="Security groups should not allow SSH (port 22) from the internet"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        security_groups = code.find_resources_by_type("aws_security_group")
        for sg in security_groups:
            ingress_rules = sg.get_attribute("ingress", [])
            if not isinstance(ingress_rules, list):
                ingress_rules = [ingress_rules]
            for rule in ingress_rules:
                if isinstance(rule, dict):
                    from_port = rule.get("from_port", 0)
                    to_port = rule.get("to_port", 0)
                    cidr_blocks = rule.get("cidr_blocks", [])
                    if (from_port <= 22 <= to_port) and ("0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks):
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Security group '{sg.resource_name}' allows SSH (port 22) from the internet",
                            line_number=sg.line_number,
                            resource_type=sg.resource_type,
                            resource_name=sg.resource_name,
                            recommendation="Restrict SSH to specific IPs or use AWS Systems Manager Session Manager"
                        ))
        return violations


class SecurityGroupRDPOpenPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SECURITY_GROUP_RDP_OPEN",
            severity=PolicySeverity.HIGH,
            description="Security groups should not allow RDP (port 3389) from the internet"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        security_groups = code.find_resources_by_type("aws_security_group")
        for sg in security_groups:
            ingress_rules = sg.get_attribute("ingress", [])
            if not isinstance(ingress_rules, list):
                ingress_rules = [ingress_rules]
            for rule in ingress_rules:
                if isinstance(rule, dict):
                    from_port = rule.get("from_port", 0)
                    to_port = rule.get("to_port", 0)
                    cidr_blocks = rule.get("cidr_blocks", [])
                    if (from_port <= 3389 <= to_port) and ("0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks):
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Security group '{sg.resource_name}' allows RDP (port 3389) from the internet",
                            line_number=sg.line_number,
                            resource_type=sg.resource_type,
                            resource_name=sg.resource_name,
                            recommendation="Restrict RDP access to specific IP ranges or use a VPN"
                        ))
        return violations


class SecurityGroupUnrestrictedEgressPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SECURITY_GROUP_UNRESTRICTED_EGRESS",
            severity=PolicySeverity.MEDIUM,
            description="Security groups should restrict outbound traffic"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        security_groups = code.find_resources_by_type("aws_security_group")
        for sg in security_groups:
            egress_rules = sg.get_attribute("egress", [])
            if not isinstance(egress_rules, list):
                egress_rules = [egress_rules]
            for rule in egress_rules:
                if isinstance(rule, dict):
                    cidr_blocks = rule.get("cidr_blocks", [])
                    from_port = rule.get("from_port", 0)
                    to_port = rule.get("to_port", 65535)
                    protocol = rule.get("protocol", "tcp")
                    if "0.0.0.0/0" in cidr_blocks and protocol == "-1":
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Security group '{sg.resource_name}' allows all outbound traffic",
                            line_number=sg.line_number,
                            resource_type=sg.resource_type,
                            resource_name=sg.resource_name,
                            recommendation="Restrict egress to specific ports and destinations needed by the application"
                        ))
        return violations


class SubnetPublicIPOnLaunchPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SUBNET_PUBLIC_IP_ON_LAUNCH",
            severity=PolicySeverity.MEDIUM,
            description="Subnets should not automatically assign public IP addresses"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        subnets = code.find_resources_by_type("aws_subnet")
        for subnet in subnets:
            map_public_ip = subnet.get_attribute("map_public_ip_on_launch", False)
            if map_public_ip:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Subnet '{subnet.resource_name}' automatically assigns public IPs on launch",
                    line_number=subnet.line_number,
                    resource_type=subnet.resource_type,
                    resource_name=subnet.resource_name,
                    recommendation="Set map_public_ip_on_launch = false and use Elastic IPs only where needed"
                ))
        return violations


class NACLAllowAllPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="NACL_ALLOWS_ALL_TRAFFIC",
            severity=PolicySeverity.MEDIUM,
            description="Network ACLs should not allow all inbound or outbound traffic"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        nacls = code.find_resources_by_type("aws_network_acl")
        for nacl in nacls:
            ingress = nacl.get_attribute("ingress", [])
            if not isinstance(ingress, list):
                ingress = [ingress]
            for rule in ingress:
                if isinstance(rule, dict):
                    cidr = rule.get("cidr_block", "")
                    protocol = rule.get("protocol", "")
                    action = rule.get("action", "")
                    if cidr == "0.0.0.0/0" and protocol == "-1" and action == "allow":
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Network ACL '{nacl.resource_name}' allows all inbound traffic",
                            line_number=nacl.line_number,
                            resource_type=nacl.resource_type,
                            resource_name=nacl.resource_name,
                            recommendation="Define specific inbound rules for required traffic only"
                        ))
        return violations


# ==============================================================================
# NEW POLICIES — DOCKER (56-65)
# ==============================================================================

class DockerLatestTagPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_LATEST_TAG",
            severity=PolicySeverity.MEDIUM,
            description="Docker images should use specific version tags, not 'latest'"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        from_instructions = [r for r in code.resources if r.resource_type == "docker_from"]
        for instr in from_instructions:
            image = instr.get_attribute("args", "")
            if isinstance(image, str) and (image.endswith(":latest") or ":" not in image):
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Dockerfile uses '{image}' — latest tag or no tag is unpredictable",
                    line_number=instr.line_number,
                    resource_type=instr.resource_type,
                    resource_name="FROM",
                    recommendation="Pin to a specific version tag e.g. python:3.10.12-slim"
                ))
        return violations


class DockerAddInsteadOfCopyPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_ADD_INSTRUCTION",
            severity=PolicySeverity.LOW,
            description="Dockerfile should use COPY instead of ADD unless extracting archives"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        add_instructions = [r for r in code.resources if r.resource_type == "docker_add"]
        for instr in add_instructions:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message="Dockerfile uses ADD instruction which can fetch remote URLs unexpectedly",
                line_number=instr.line_number,
                resource_type=instr.resource_type,
                resource_name="ADD",
                recommendation="Replace ADD with COPY unless you need tar extraction or URL fetching"
            ))
        return violations


class DockerHealthCheckMissingPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_NO_HEALTHCHECK",
            severity=PolicySeverity.LOW,
            description="Dockerfiles should define a HEALTHCHECK instruction"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        healthcheck_instructions = [r for r in code.resources if r.resource_type == "docker_healthcheck"]
        if not healthcheck_instructions and len(code.resources) > 0:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message="Dockerfile does not define a HEALTHCHECK instruction",
                line_number=None,
                resource_type="dockerfile",
                resource_name="HEALTHCHECK",
                recommendation="Add HEALTHCHECK to allow Docker and orchestrators to detect unhealthy containers"
            ))
        return violations


class DockerSecretsInEnvPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_SECRET_IN_ENV",
            severity=PolicySeverity.CRITICAL,
            description="Dockerfiles should not expose secrets in ENV instructions"
        )
        self.secret_patterns = [
            r'password', r'secret', r'api_key', r'token', r'access_key'
        ]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        env_instructions = [r for r in code.resources if r.resource_type == "docker_env"]
        for instr in env_instructions:
            args = instr.get_attribute("args", "")
            if isinstance(args, str):
                for pattern in self.secret_patterns:
                    if re.search(pattern, args, re.IGNORECASE):
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Dockerfile ENV instruction may expose a secret: {args[:50]}",
                            line_number=instr.line_number,
                            resource_type=instr.resource_type,
                            resource_name="ENV",
                            recommendation="Use Docker secrets or runtime environment injection instead of ENV"
                        ))
                        break
        return violations


class DockerExposedPrivilegedPortPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_PRIVILEGED_PORT_EXPOSED",
            severity=PolicySeverity.MEDIUM,
            description="Dockerfiles should not expose privileged ports (below 1024)"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        expose_instructions = [r for r in code.resources if r.resource_type == "docker_expose"]
        for instr in expose_instructions:
            args = instr.get_attribute("args", "")
            if isinstance(args, str):
                try:
                    port = int(args.split("/")[0])
                    if port < 1024:
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Dockerfile exposes privileged port {port} (requires root)",
                            line_number=instr.line_number,
                            resource_type=instr.resource_type,
                            resource_name="EXPOSE",
                            recommendation="Use ports above 1024 and map them at runtime with -p flag"
                        ))
                except ValueError:
                    pass
        return violations


class DockerNoWorkdirPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_NO_WORKDIR",
            severity=PolicySeverity.LOW,
            description="Dockerfiles should define a WORKDIR instruction"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        workdir_instructions = [r for r in code.resources if r.resource_type == "docker_workdir"]
        if not workdir_instructions and len(code.resources) > 0:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message="Dockerfile does not define a WORKDIR instruction",
                line_number=None,
                resource_type="dockerfile",
                resource_name="WORKDIR",
                recommendation="Add WORKDIR /app or similar to set a predictable working directory"
            ))
        return violations


class DockerSecretsInArgPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_SECRET_IN_ARG",
            severity=PolicySeverity.HIGH,
            description="Dockerfile ARG should not be used to pass secrets as they appear in image history"
        )
        self.secret_patterns = [
            r'password', r'secret', r'api_key', r'token', r'access_key', r'private_key'
        ]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        arg_instructions = [r for r in code.resources if r.resource_type == "docker_arg"]
        for instr in arg_instructions:
            args = instr.get_attribute("args", "")
            if isinstance(args, str):
                for pattern in self.secret_patterns:
                    if re.search(pattern, args, re.IGNORECASE):
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Dockerfile ARG '{args}' may expose a secret in image build history",
                            line_number=instr.line_number,
                            resource_type=instr.resource_type,
                            resource_name="ARG",
                            recommendation="Use Docker BuildKit secrets (--secret) instead of ARG for sensitive values"
                        ))
                        break
        return violations


class DockerMultiStageMissingPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DOCKER_NO_MULTI_STAGE",
            severity=PolicySeverity.LOW,
            description="Production Dockerfiles should use multi-stage builds to minimize image size"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "dockerfile":
            return violations
        from_instructions = [r for r in code.resources if r.resource_type == "docker_from"]
        if len(from_instructions) == 1:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message="Dockerfile uses a single-stage build which may include build tools in the final image",
                line_number=from_instructions[0].line_number if from_instructions else None,
                resource_type="dockerfile",
                resource_name="FROM",
                recommendation="Use multi-stage builds to separate build environment from runtime image"
            ))
        return violations


# ==============================================================================
# NEW POLICIES — KUBERNETES (66-80)
# ==============================================================================

class K8sReadOnlyRootFilesystemPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_NO_READONLY_ROOT_FILESYSTEM",
            severity=PolicySeverity.MEDIUM,
            description="Kubernetes containers should use a read-only root filesystem"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                security_context = resource.get_attribute("securityContext", {})
                read_only = security_context.get("readOnlyRootFilesystem", False) if isinstance(security_context, dict) else False
                if not read_only:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' does not use a read-only root filesystem",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Set securityContext.readOnlyRootFilesystem: true and use emptyDir for writable paths"
                    ))
        return violations


class K8sAllowPrivilegeEscalationPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_ALLOW_PRIVILEGE_ESCALATION",
            severity=PolicySeverity.HIGH,
            description="Kubernetes containers should not allow privilege escalation"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                security_context = resource.get_attribute("securityContext", {})
                allow_escalation = security_context.get("allowPrivilegeEscalation", True) if isinstance(security_context, dict) else True
                if allow_escalation:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' allows privilege escalation",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Set securityContext.allowPrivilegeEscalation: false"
                    ))
        return violations


class K8sRunAsRootPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_RUN_AS_ROOT",
            severity=PolicySeverity.HIGH,
            description="Kubernetes containers should not run as root user"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                security_context = resource.get_attribute("securityContext", {})
                run_as_non_root = security_context.get("runAsNonRoot", False) if isinstance(security_context, dict) else False
                run_as_user = security_context.get("runAsUser", 0) if isinstance(security_context, dict) else 0
                if not run_as_non_root and run_as_user == 0:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' may run as root (UID 0)",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID"
                    ))
        return violations


class K8sHostPIDPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_HOST_PID_ENABLED",
            severity=PolicySeverity.HIGH,
            description="Pods should not share the host PID namespace"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        host_pid_resources = [r for r in code.resources if r.resource_type == "k8s_host_pid"]
        for resource in host_pid_resources:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message=f"Pod '{resource.resource_name}' uses host PID namespace",
                line_number=resource.line_number,
                resource_type=resource.resource_type,
                resource_name=resource.resource_name,
                recommendation="Set hostPID: false or remove the field to isolate the pod's process namespace"
            ))
        return violations


class K8sHostIPCPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_HOST_IPC_ENABLED",
            severity=PolicySeverity.HIGH,
            description="Pods should not share the host IPC namespace"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        host_ipc_resources = [r for r in code.resources if r.resource_type == "k8s_host_ipc"]
        for resource in host_ipc_resources:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message=f"Pod '{resource.resource_name}' uses host IPC namespace",
                line_number=resource.line_number,
                resource_type=resource.resource_type,
                resource_name=resource.resource_name,
                recommendation="Set hostIPC: false or remove the field"
            ))
        return violations


class K8sImagePullPolicyPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_IMAGE_PULL_POLICY_NOT_ALWAYS",
            severity=PolicySeverity.LOW,
            description="Kubernetes containers should use imagePullPolicy: Always for latest tags"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                image = resource.get_attribute("image", "")
                pull_policy = resource.get_attribute("imagePullPolicy", "IfNotPresent")
                if (":latest" in str(image) or ":" not in str(image)) and pull_policy != "Always":
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' uses latest tag but imagePullPolicy is not Always",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Set imagePullPolicy: Always when using latest or untagged images"
                    ))
        return violations


class K8sLivenessProbePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_NO_LIVENESS_PROBE",
            severity=PolicySeverity.LOW,
            description="Kubernetes containers should define liveness probes"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                liveness = resource.get_attribute("livenessProbe")
                if not liveness:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' does not have a liveness probe",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Add a livenessProbe so Kubernetes can restart unhealthy containers"
                    ))
        return violations


class K8sReadinessProbePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_NO_READINESS_PROBE",
            severity=PolicySeverity.LOW,
            description="Kubernetes containers should define readiness probes"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                readiness = resource.get_attribute("readinessProbe")
                if not readiness:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' does not have a readiness probe",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Add a readinessProbe so Kubernetes knows when the container is ready for traffic"
                    ))
        return violations


class K8sDefaultNamespacePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_DEFAULT_NAMESPACE",
            severity=PolicySeverity.LOW,
            description="Kubernetes resources should not be deployed to the default namespace"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            namespace = resource.get_attribute("namespace", "default")
            if namespace == "default":
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Resource '{resource.resource_name}' is deployed to the default namespace",
                    line_number=resource.line_number,
                    resource_type=resource.resource_type,
                    resource_name=resource.resource_name,
                    recommendation="Create a dedicated namespace for your application workloads"
                ))
        return violations


class K8sAutomountServiceAccountPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_AUTOMOUNT_SERVICE_ACCOUNT",
            severity=PolicySeverity.MEDIUM,
            description="Pods should not automount service account tokens unless required"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        automount_resources = [r for r in code.resources if r.resource_type == "k8s_automount_token"]
        for resource in automount_resources:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message=f"Pod '{resource.resource_name}' automounts service account token",
                line_number=resource.line_number,
                resource_type=resource.resource_type,
                resource_name=resource.resource_name,
                recommendation="Set automountServiceAccountToken: false unless the pod needs API access"
            ))
        return violations


class K8sCapabilitiesPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_DANGEROUS_CAPABILITIES",
            severity=PolicySeverity.HIGH,
            description="Kubernetes containers should not add dangerous Linux capabilities"
        )
        self.dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                security_context = resource.get_attribute("securityContext", {})
                capabilities = security_context.get("capabilities", {}) if isinstance(security_context, dict) else {}
                add_caps = capabilities.get("add", []) if isinstance(capabilities, dict) else []
                for cap in add_caps:
                    if cap in self.dangerous_caps:
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Container '{resource.resource_name}' adds dangerous capability: {cap}",
                            line_number=resource.line_number,
                            resource_type=resource.resource_type,
                            resource_name=resource.resource_name,
                            recommendation=f"Remove capability {cap} and use more specific permissions instead"
                        ))
        return violations


class K8sResourceRequestsMissingPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="K8S_NO_RESOURCE_REQUESTS",
            severity=PolicySeverity.LOW,
            description="Kubernetes containers should define resource requests"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "kubernetes":
            return violations
        for resource in code.resources:
            if "container" in resource.resource_type:
                resources_config = resource.get_attribute("resources", {})
                requests = resources_config.get("requests", {}) if isinstance(resources_config, dict) else {}
                if not requests:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Container '{resource.resource_name}' has no resource requests defined",
                        line_number=resource.line_number,
                        resource_type=resource.resource_type,
                        resource_name=resource.resource_name,
                        recommendation="Add resources.requests with cpu and memory values for proper scheduling"
                    ))
        return violations


# ==============================================================================
# NEW POLICIES — AWS CLOUDTRAIL / MONITORING (81-88)
# ==============================================================================

class CloudTrailDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="CLOUDTRAIL_DISABLED",
            severity=PolicySeverity.CRITICAL,
            description="AWS CloudTrail should be enabled for audit logging"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        trails = code.find_resources_by_type("aws_cloudtrail")
        for trail in trails:
            enabled = trail.get_attribute("enable_logging", True)
            if not enabled:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"CloudTrail '{trail.resource_name}' has logging disabled",
                    line_number=trail.line_number,
                    resource_type=trail.resource_type,
                    resource_name=trail.resource_name,
                    recommendation="Set enable_logging = true to maintain audit trail of all API calls"
                ))
        return violations


class CloudTrailLogValidationPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="CLOUDTRAIL_LOG_VALIDATION_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="CloudTrail should have log file validation enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        trails = code.find_resources_by_type("aws_cloudtrail")
        for trail in trails:
            validation = trail.get_attribute("enable_log_file_validation", False)
            if not validation:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"CloudTrail '{trail.resource_name}' does not have log file validation enabled",
                    line_number=trail.line_number,
                    resource_type=trail.resource_type,
                    resource_name=trail.resource_name,
                    recommendation="Set enable_log_file_validation = true to detect log tampering"
                ))
        return violations


class CloudTrailMultiRegionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="CLOUDTRAIL_NOT_MULTI_REGION",
            severity=PolicySeverity.MEDIUM,
            description="CloudTrail should be enabled in all regions"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        trails = code.find_resources_by_type("aws_cloudtrail")
        for trail in trails:
            multi_region = trail.get_attribute("is_multi_region_trail", False)
            if not multi_region:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"CloudTrail '{trail.resource_name}' is not configured for all regions",
                    line_number=trail.line_number,
                    resource_type=trail.resource_type,
                    resource_name=trail.resource_name,
                    recommendation="Set is_multi_region_trail = true to capture events from all AWS regions"
                ))
        return violations


class CloudWatchAlarmMissingPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="CLOUDWATCH_NO_ALARMS",
            severity=PolicySeverity.LOW,
            description="Critical infrastructure should have CloudWatch alarms configured"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        # Disabled — requires separate Terraform files for alarms, too noisy
        return []


class GuardDutyDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="GUARDDUTY_DISABLED",
            severity=PolicySeverity.HIGH,
            description="AWS GuardDuty should be enabled for threat detection"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        guardduty = code.find_resources_by_type("aws_guardduty_detector")
        for detector in guardduty:
            enabled = detector.get_attribute("enable", True)
            if not enabled:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"GuardDuty detector '{detector.resource_name}' is disabled",
                    line_number=detector.line_number,
                    resource_type=detector.resource_type,
                    resource_name=detector.resource_name,
                    recommendation="Set enable = true to activate GuardDuty threat detection"
                ))
        return violations


class SecurityHubDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SECURITY_HUB_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="AWS Security Hub should be enabled for centralized security findings"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        # Only flag if a guardduty detector exists (meaning AWS security is being configured)
        # but Security Hub is missing — avoids false positives on simple configs
        violations = []
        if code.code_type not in ("terraform",):
            return violations
        guardduty = code.find_resources_by_type("aws_guardduty_detector")
        security_hub = code.find_resources_by_type("aws_securityhub_account")
        if guardduty and not security_hub:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message="AWS Security Hub is not enabled in this configuration",
                line_number=None,
                resource_type="aws_securityhub_account",
                resource_name="security_hub",
                recommendation="Add aws_securityhub_account resource to enable centralized security findings"
            ))
        return violations


class ConfigServiceDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="AWS_CONFIG_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="AWS Config should be enabled to track configuration changes"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        config_recorders = code.find_resources_by_type("aws_config_configuration_recorder")
        for recorder in config_recorders:
            status = code.find_resources_by_type("aws_config_configuration_recorder_status")
            enabled = False
            for s in status:
                if s.get_attribute("is_enabled", False):
                    enabled = True
            if not enabled:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"AWS Config recorder '{recorder.resource_name}' is not enabled",
                    line_number=recorder.line_number,
                    resource_type=recorder.resource_type,
                    resource_name=recorder.resource_name,
                    recommendation="Add aws_config_configuration_recorder_status with is_enabled = true"
                ))
        return violations


class KMSKeyRotationPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="KMS_KEY_ROTATION_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="KMS keys should have automatic key rotation enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        kms_keys = code.find_resources_by_type("aws_kms_key")
        for key in kms_keys:
            rotation = key.get_attribute("enable_key_rotation", False)
            if not rotation:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"KMS key '{key.resource_name}' does not have automatic rotation enabled",
                    line_number=key.line_number,
                    resource_type=key.resource_type,
                    resource_name=key.resource_name,
                    recommendation="Set enable_key_rotation = true to rotate KMS keys annually"
                ))
        return violations


# ==============================================================================
# NEW POLICIES — AWS ELB / ALB / WAF (89-95)
# ==============================================================================

class ALBHTTPSOnlyPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ALB_HTTP_LISTENER",
            severity=PolicySeverity.HIGH,
            description="Load balancers should only accept HTTPS traffic"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        listeners = code.find_resources_by_type("aws_lb_listener")
        for listener in listeners:
            protocol = listener.get_attribute("protocol", "HTTP")
            port = listener.get_attribute("port", 80)
            if str(protocol).upper() == "HTTP" and port != 80:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Load balancer listener '{listener.resource_name}' uses HTTP instead of HTTPS",
                    line_number=listener.line_number,
                    resource_type=listener.resource_type,
                    resource_name=listener.resource_name,
                    recommendation="Change protocol to HTTPS and configure an SSL certificate"
                ))
        return violations


class ALBAccessLogsDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ALB_ACCESS_LOGS_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="Load balancers should have access logs enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        load_balancers = code.find_resources_by_type("aws_lb")
        for lb in load_balancers:
            access_logs = lb.get_attribute("access_logs", {})
            enabled = access_logs.get("enabled", False) if isinstance(access_logs, dict) else False
            if not enabled:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Load balancer '{lb.resource_name}' does not have access logs enabled",
                    line_number=lb.line_number,
                    resource_type=lb.resource_type,
                    resource_name=lb.resource_name,
                    recommendation="Enable access_logs with an S3 bucket target for audit and troubleshooting"
                ))
        return violations


class WAFMissingPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="WAF_NOT_ASSOCIATED",
            severity=PolicySeverity.MEDIUM,
            description="Public-facing load balancers should be associated with a WAF"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        load_balancers = code.find_resources_by_type("aws_lb")
        waf_associations = code.find_resources_by_type("aws_wafv2_web_acl_association")
        lb_names_with_waf = set()
        for assoc in waf_associations:
            resource_arn = assoc.get_attribute("resource_arn", "")
            lb_names_with_waf.add(resource_arn)
        for lb in load_balancers:
            internal = lb.get_attribute("internal", False)
            if not internal and lb.resource_name not in lb_names_with_waf:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Public load balancer '{lb.resource_name}' is not associated with a WAF",
                    line_number=lb.line_number,
                    resource_type=lb.resource_type,
                    resource_name=lb.resource_name,
                    recommendation="Associate an aws_wafv2_web_acl with the load balancer for protection against web attacks"
                ))
        return violations


class LBDeletionProtectionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="LB_DELETION_PROTECTION_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="Load balancers should have deletion protection enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        load_balancers = code.find_resources_by_type("aws_lb")
        for lb in load_balancers:
            deletion_protection = lb.get_attribute("enable_deletion_protection", False)
            if not deletion_protection:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Load balancer '{lb.resource_name}' does not have deletion protection enabled",
                    line_number=lb.line_number,
                    resource_type=lb.resource_type,
                    resource_name=lb.resource_name,
                    recommendation="Set enable_deletion_protection = true to prevent accidental deletion"
                ))
        return violations


class ALBTLSPolicyPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ALB_WEAK_TLS_POLICY",
            severity=PolicySeverity.HIGH,
            description="Load balancer HTTPS listeners should use strong TLS policies"
        )
        self.weak_policies = ["ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-TLS-1-0-2015-04"]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        listeners = code.find_resources_by_type("aws_lb_listener")
        for listener in listeners:
            ssl_policy = listener.get_attribute("ssl_policy", "")
            if ssl_policy in self.weak_policies:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Listener '{listener.resource_name}' uses weak TLS policy: {ssl_policy}",
                    line_number=listener.line_number,
                    resource_type=listener.resource_type,
                    resource_name=listener.resource_name,
                    recommendation="Use ELBSecurityPolicy-TLS13-1-2-2021-06 or newer for strong TLS"
                ))
        return violations


class Route53DNSSECPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ROUTE53_DNSSEC_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="Route53 hosted zones should have DNSSEC signing enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        hosted_zones = code.find_resources_by_type("aws_route53_zone")
        dnssec_configs = code.find_resources_by_type("aws_route53_hosted_zone_dnssec")
        zones_with_dnssec = set()
        for config in dnssec_configs:
            zone_id = config.get_attribute("hosted_zone_id", "")
            zones_with_dnssec.add(zone_id)
        for zone in hosted_zones:
            private = zone.get_attribute("vpc", None)
            if not private and zone.resource_name not in zones_with_dnssec:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Route53 zone '{zone.resource_name}' does not have DNSSEC enabled",
                    line_number=zone.line_number,
                    resource_type=zone.resource_type,
                    resource_name=zone.resource_name,
                    recommendation="Add aws_route53_hosted_zone_dnssec to protect against DNS spoofing"
                ))
        return violations


class ELBCrossZoneLoadBalancingPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ELB_CROSS_ZONE_DISABLED",
            severity=PolicySeverity.LOW,
            description="Load balancers should have cross-zone load balancing enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        load_balancers = code.find_resources_by_type("aws_lb")
        for lb in load_balancers:
            cross_zone = lb.get_attribute("enable_cross_zone_load_balancing", False)
            lb_type = lb.get_attribute("load_balancer_type", "application")
            if lb_type == "network" and not cross_zone:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Network load balancer '{lb.resource_name}' does not have cross-zone load balancing enabled",
                    line_number=lb.line_number,
                    resource_type=lb.resource_type,
                    resource_name=lb.resource_name,
                    recommendation="Set enable_cross_zone_load_balancing = true for even traffic distribution"
                ))
        return violations


# ==============================================================================
# NEW POLICIES — TERRAFORM GENERAL (96-100)
# ==============================================================================

class TerraformBackendNotConfiguredPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="TERRAFORM_NO_REMOTE_BACKEND",
            severity=PolicySeverity.MEDIUM,
            description="Terraform state should be stored in a remote backend"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "terraform":
            return violations
        terraform_blocks = code.find_resources_by_type("terraform")
        has_backend = False
        for block in terraform_blocks:
            backend = block.get_attribute("backend")
            if backend:
                has_backend = True
        if terraform_blocks and not has_backend:
            violations.append(PolicyViolation(
                rule_id=self.rule_id,
                severity=self.severity,
                message="Terraform configuration does not define a remote backend",
                line_number=None,
                resource_type="terraform",
                resource_name="backend",
                recommendation="Configure a remote backend (S3, Terraform Cloud) to store state securely and enable team collaboration"
            ))
        return violations


class TerraformProviderVersionPinnedPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="TERRAFORM_PROVIDER_NOT_PINNED",
            severity=PolicySeverity.LOW,
            description="Terraform provider versions should be pinned to avoid unexpected upgrades"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "terraform":
            return violations
        required_providers = code.find_resources_by_type("required_providers")
        for provider_block in required_providers:
            for provider_name, provider_config in provider_block.attributes.items():
                if isinstance(provider_config, dict):
                    version = provider_config.get("version", "")
                    if not version or version == "*":
                        violations.append(PolicyViolation(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message=f"Terraform provider '{provider_name}' does not have a pinned version",
                            line_number=provider_block.line_number,
                            resource_type="required_providers",
                            resource_name=provider_name,
                            recommendation=f"Pin the provider version e.g. version = '~> 5.0' to avoid breaking changes"
                        ))
        return violations


class TerraformOutputSensitivePolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="TERRAFORM_OUTPUT_NOT_SENSITIVE",
            severity=PolicySeverity.MEDIUM,
            description="Terraform outputs containing secrets should be marked as sensitive"
        )
        self.secret_keywords = ["password", "secret", "key", "token", "credential"]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "terraform":
            return violations
        outputs = code.find_resources_by_type("output")
        for output in outputs:
            name = output.resource_name.lower()
            sensitive = output.get_attribute("sensitive", False)
            for keyword in self.secret_keywords:
                if keyword in name and not sensitive:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Terraform output '{output.resource_name}' may contain a secret but is not marked sensitive",
                        line_number=output.line_number,
                        resource_type="output",
                        resource_name=output.resource_name,
                        recommendation="Add sensitive = true to prevent the value from appearing in logs and plan output"
                    ))
                    break
        return violations


class TerraformVariableDefaultSecretPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="TERRAFORM_VARIABLE_DEFAULT_SECRET",
            severity=PolicySeverity.HIGH,
            description="Terraform variables for secrets should not have default values"
        )
        self.secret_keywords = ["password", "secret", "key", "token", "credential"]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "terraform":
            return violations
        variables = code.find_resources_by_type("variable")
        for variable in variables:
            name = variable.resource_name.lower()
            default = variable.get_attribute("default")
            for keyword in self.secret_keywords:
                if keyword in name and default is not None and default != "":
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Terraform variable '{variable.resource_name}' contains a secret with a default value",
                        line_number=variable.line_number,
                        resource_type="variable",
                        resource_name=variable.resource_name,
                        recommendation="Remove the default value and inject secrets via environment variables or a secrets manager"
                    ))
                    break
        return violations


class TerraformSensitiveVariableNotMarkedPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="TERRAFORM_VARIABLE_NOT_SENSITIVE",
            severity=PolicySeverity.MEDIUM,
            description="Terraform variables for secrets should be marked as sensitive"
        )
        self.secret_keywords = ["password", "secret", "key", "token", "credential"]

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        if code.code_type != "terraform":
            return violations
        variables = code.find_resources_by_type("variable")
        for variable in variables:
            name = variable.resource_name.lower()
            sensitive = variable.get_attribute("sensitive", False)
            for keyword in self.secret_keywords:
                if keyword in name and not sensitive:
                    violations.append(PolicyViolation(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Terraform variable '{variable.resource_name}' looks like a secret but is not marked sensitive",
                        line_number=variable.line_number,
                        resource_type="variable",
                        resource_name=variable.resource_name,
                        recommendation="Add sensitive = true to prevent the value from being shown in plan/apply output"
                    ))
                    break
        return violations


# ==============================================================================
# NEW POLICIES — AWS EKS / ECS / LAMBDA (additional)
# ==============================================================================

class EKSPublicEndpointPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EKS_PUBLIC_ENDPOINT",
            severity=PolicySeverity.HIGH,
            description="EKS cluster API server endpoint should not be publicly accessible"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        clusters = code.find_resources_by_type("aws_eks_cluster")
        for cluster in clusters:
            vpc_config = cluster.get_attribute("vpc_config", {})
            public_access = vpc_config.get("endpoint_public_access", True) if isinstance(vpc_config, dict) else True
            if public_access:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EKS cluster '{cluster.resource_name}' has a publicly accessible API endpoint",
                    line_number=cluster.line_number,
                    resource_type=cluster.resource_type,
                    resource_name=cluster.resource_name,
                    recommendation="Set vpc_config { endpoint_public_access = false } and use VPN for cluster access"
                ))
        return violations


class EKSLoggingDisabledPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="EKS_LOGGING_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="EKS clusters should have control plane logging enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        clusters = code.find_resources_by_type("aws_eks_cluster")
        for cluster in clusters:
            enabled_logs = cluster.get_attribute("enabled_cluster_log_types", [])
            required_logs = {"api", "audit", "authenticator"}
            missing = required_logs - set(enabled_logs)
            if missing:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"EKS cluster '{cluster.resource_name}' is missing log types: {', '.join(missing)}",
                    line_number=cluster.line_number,
                    resource_type=cluster.resource_type,
                    resource_name=cluster.resource_name,
                    recommendation="Add api, audit, and authenticator to enabled_cluster_log_types"
                ))
        return violations


class LambdaPublicAccessPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="LAMBDA_PUBLIC_ACCESS",
            severity=PolicySeverity.HIGH,
            description="Lambda functions should not be publicly accessible"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        permissions = code.find_resources_by_type("aws_lambda_permission")
        for perm in permissions:
            principal = perm.get_attribute("principal", "")
            if principal == "*":
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Lambda permission '{perm.resource_name}' allows public invocation",
                    line_number=perm.line_number,
                    resource_type=perm.resource_type,
                    resource_name=perm.resource_name,
                    recommendation="Restrict the principal to specific AWS services or accounts"
                ))
        return violations


class LambdaEnvSecretsPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="LAMBDA_ENV_SECRETS",
            severity=PolicySeverity.CRITICAL,
            description="Lambda environment variables should not contain hardcoded secrets"
        )
        self.secret_patterns = [r'password', r'secret', r'api_key', r'token', r'access_key']

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        functions = code.find_resources_by_type("aws_lambda_function")
        for func in functions:
            env = func.get_attribute("environment", {})
            variables = env.get("variables", {}) if isinstance(env, dict) else {}
            if isinstance(variables, dict):
                for var_name, var_value in variables.items():
                    for pattern in self.secret_patterns:
                        if re.search(pattern, var_name, re.IGNORECASE) and isinstance(var_value, str) and var_value:
                            violations.append(PolicyViolation(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                message=f"Lambda function '{func.resource_name}' has secret in env variable: {var_name}",
                                line_number=func.line_number,
                                resource_type=func.resource_type,
                                resource_name=func.resource_name,
                                recommendation="Use AWS Secrets Manager or SSM Parameter Store instead of environment variables for secrets"
                            ))
                            break
        return violations


class LambdaReservedConcurrencyPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="LAMBDA_NO_RESERVED_CONCURRENCY",
            severity=PolicySeverity.LOW,
            description="Lambda functions should have reserved concurrency configured"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        functions = code.find_resources_by_type("aws_lambda_function")
        for func in functions:
            concurrency = func.get_attribute("reserved_concurrent_executions", -1)
            if concurrency == -1:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Lambda function '{func.resource_name}' has no reserved concurrency limit",
                    line_number=func.line_number,
                    resource_type=func.resource_type,
                    resource_name=func.resource_name,
                    recommendation="Set reserved_concurrent_executions to prevent the function from consuming all account concurrency"
                ))
        return violations


class ECSTaskPrivilegedPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ECS_TASK_PRIVILEGED",
            severity=PolicySeverity.HIGH,
            description="ECS task containers should not run in privileged mode"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        task_definitions = code.find_resources_by_type("aws_ecs_task_definition")
        for task in task_definitions:
            container_defs = str(task.get_attribute("container_definitions", ""))
            if '"privileged": true' in container_defs or '"privileged":true' in container_defs:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"ECS task definition '{task.resource_name}' has a privileged container",
                    line_number=task.line_number,
                    resource_type=task.resource_type,
                    resource_name=task.resource_name,
                    recommendation="Remove privileged: true from the container definition"
                ))
        return violations


class ECSTaskReadonlyRootPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ECS_TASK_NO_READONLY_ROOT",
            severity=PolicySeverity.MEDIUM,
            description="ECS task containers should use a read-only root filesystem"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        task_definitions = code.find_resources_by_type("aws_ecs_task_definition")
        for task in task_definitions:
            container_defs = str(task.get_attribute("container_definitions", ""))
            if '"readonlyRootFilesystem": false' in container_defs or '"readonlyRootFilesystem":false' in container_defs:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"ECS task definition '{task.resource_name}' has readonlyRootFilesystem set to false",
                    line_number=task.line_number,
                    resource_type=task.resource_type,
                    resource_name=task.resource_name,
                    recommendation="Set readonlyRootFilesystem: true in the container definition"
                ))
        return violations


class SNSTopicEncryptionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SNS_TOPIC_NOT_ENCRYPTED",
            severity=PolicySeverity.MEDIUM,
            description="SNS topics should be encrypted with KMS"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        topics = code.find_resources_by_type("aws_sns_topic")
        for topic in topics:
            kms_key = topic.get_attribute("kms_master_key_id", "")
            if not kms_key:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"SNS topic '{topic.resource_name}' is not encrypted with KMS",
                    line_number=topic.line_number,
                    resource_type=topic.resource_type,
                    resource_name=topic.resource_name,
                    recommendation="Set kms_master_key_id to a KMS key ARN for message encryption at rest"
                ))
        return violations


class SQSQueueEncryptionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SQS_QUEUE_NOT_ENCRYPTED",
            severity=PolicySeverity.MEDIUM,
            description="SQS queues should be encrypted with KMS"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        queues = code.find_resources_by_type("aws_sqs_queue")
        for queue in queues:
            kms_key = queue.get_attribute("kms_master_key_id", "")
            if not kms_key:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"SQS queue '{queue.resource_name}' is not encrypted with KMS",
                    line_number=queue.line_number,
                    resource_type=queue.resource_type,
                    resource_name=queue.resource_name,
                    recommendation="Set kms_master_key_id to encrypt queue messages at rest"
                ))
        return violations


class DynamoDBEncryptionPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="DYNAMODB_NOT_ENCRYPTED",
            severity=PolicySeverity.HIGH,
            description="DynamoDB tables should have encryption enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        tables = code.find_resources_by_type("aws_dynamodb_table")
        for table in tables:
            sse_spec = table.get_attribute("server_side_encryption", {})
            enabled = sse_spec.get("enabled", False) if isinstance(sse_spec, dict) else False
            if not enabled:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"DynamoDB table '{table.resource_name}' does not have server-side encryption enabled",
                    line_number=table.line_number,
                    resource_type=table.resource_type,
                    resource_name=table.resource_name,
                    recommendation="Add server_side_encryption { enabled = true } to the table definition"
                ))
        return violations


class ElastiCacheEncryptionInTransitPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ELASTICACHE_NO_ENCRYPTION_TRANSIT",
            severity=PolicySeverity.HIGH,
            description="ElastiCache clusters should encrypt data in transit"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        clusters = code.find_resources_by_type("aws_elasticache_replication_group")
        for cluster in clusters:
            transit_encryption = cluster.get_attribute("transit_encryption_enabled", False)
            if not transit_encryption:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"ElastiCache cluster '{cluster.resource_name}' does not encrypt data in transit",
                    line_number=cluster.line_number,
                    resource_type=cluster.resource_type,
                    resource_name=cluster.resource_name,
                    recommendation="Set transit_encryption_enabled = true to encrypt data between nodes and clients"
                ))
        return violations


class ElastiCacheEncryptionAtRestPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ELASTICACHE_NO_ENCRYPTION_REST",
            severity=PolicySeverity.HIGH,
            description="ElastiCache clusters should encrypt data at rest"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        clusters = code.find_resources_by_type("aws_elasticache_replication_group")
        for cluster in clusters:
            at_rest_encryption = cluster.get_attribute("at_rest_encryption_enabled", False)
            if not at_rest_encryption:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"ElastiCache cluster '{cluster.resource_name}' does not encrypt data at rest",
                    line_number=cluster.line_number,
                    resource_type=cluster.resource_type,
                    resource_name=cluster.resource_name,
                    recommendation="Set at_rest_encryption_enabled = true to encrypt cached data"
                ))
        return violations


class ECRImageScanningPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ECR_IMAGE_SCANNING_DISABLED",
            severity=PolicySeverity.MEDIUM,
            description="ECR repositories should have image scanning on push enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        repos = code.find_resources_by_type("aws_ecr_repository")
        for repo in repos:
            scan_config = repo.get_attribute("image_scanning_configuration", {})
            scan_on_push = scan_config.get("scan_on_push", False) if isinstance(scan_config, dict) else False
            if not scan_on_push:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"ECR repository '{repo.resource_name}' does not scan images on push",
                    line_number=repo.line_number,
                    resource_type=repo.resource_type,
                    resource_name=repo.resource_name,
                    recommendation="Set image_scanning_configuration { scan_on_push = true }"
                ))
        return violations


class ECRImageMutabilityPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="ECR_IMAGE_MUTABLE",
            severity=PolicySeverity.MEDIUM,
            description="ECR repositories should use immutable image tags"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        repos = code.find_resources_by_type("aws_ecr_repository")
        for repo in repos:
            mutability = repo.get_attribute("image_tag_mutability", "MUTABLE")
            if mutability == "MUTABLE":
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"ECR repository '{repo.resource_name}' allows mutable image tags",
                    line_number=repo.line_number,
                    resource_type=repo.resource_type,
                    resource_name=repo.resource_name,
                    recommendation="Set image_tag_mutability = 'IMMUTABLE' to prevent tag overwriting"
                ))
        return violations


class SecretManagerRotationPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="SECRETS_MANAGER_NO_ROTATION",
            severity=PolicySeverity.MEDIUM,
            description="Secrets Manager secrets should have automatic rotation enabled"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        secrets = code.find_resources_by_type("aws_secretsmanager_secret")
        rotation_configs = code.find_resources_by_type("aws_secretsmanager_secret_rotation")
        secrets_with_rotation = set()
        for rot in rotation_configs:
            secret_id = rot.get_attribute("secret_id", "")
            secrets_with_rotation.add(secret_id)
        for secret in secrets:
            if secret.resource_name not in secrets_with_rotation:
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Secrets Manager secret '{secret.resource_name}' does not have automatic rotation configured",
                    line_number=secret.line_number,
                    resource_type=secret.resource_type,
                    resource_name=secret.resource_name,
                    recommendation="Add aws_secretsmanager_secret_rotation to automatically rotate the secret"
                ))
        return violations


class CloudFrontHTTPSPolicy(BasePolicy):
    def __init__(self):
        super().__init__(
            rule_id="CLOUDFRONT_HTTP_ALLOWED",
            severity=PolicySeverity.HIGH,
            description="CloudFront distributions should redirect HTTP to HTTPS"
        )

    def check(self, code: NormalizedCode) -> List[PolicyViolation]:
        violations = []
        distributions = code.find_resources_by_type("aws_cloudfront_distribution")
        for dist in distributions:
            viewer_cert = dist.get_attribute("viewer_certificate", {})
            default_cache = dist.get_attribute("default_cache_behavior", {})
            viewer_protocol = default_cache.get("viewer_protocol_policy", "allow-all") if isinstance(default_cache, dict) else "allow-all"
            if viewer_protocol == "allow-all":
                violations.append(PolicyViolation(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"CloudFront distribution '{dist.resource_name}' allows HTTP traffic",
                    line_number=dist.line_number,
                    resource_type=dist.resource_type,
                    resource_name=dist.resource_name,
                    recommendation="Set viewer_protocol_policy to 'redirect-to-https' or 'https-only'"
                ))
        return violations


# ==============================================================================
# REGISTRY — returns all 100 policies
# ==============================================================================

def get_all_policies() -> List[BasePolicy]:
    return [
        # Original 12
        PublicS3BucketPolicy(),
        HardcodedSecretsPolicy(),
        UnencryptedStoragePolicy(),
        RootDockerUserPolicy(),
        MissingTagsPolicy(),
        InsecureSecurityGroupPolicy(),
        MissingLoggingPolicy(),
        PublicDatabasePolicy(),
        ExpensiveInstancePolicy(),
        PrivilegedContainerPolicy(),
        HostNetworkPolicy(),
        MissingResourceLimitsPolicy(),

        # S3 (5 new)
        S3VersioningDisabledPolicy(),
        S3MFADeleteDisabledPolicy(),
        S3TransferAccelerationPolicy(),
        S3BlockPublicAclPolicy(),
        S3CrossRegionReplicationPolicy(),

        # EC2 / Compute (7 new)
        EC2IMDSv1EnabledPolicy(),
        EC2PublicIPAssignedPolicy(),
        EC2NoKeyPairPolicy(),
        EC2EBSEncryptionPolicy(),
        EC2DetailedMonitoringPolicy(),
        EC2TerminationProtectionPolicy(),
        EC2UserDataSecretsPolicy(),

        # RDS / Database (7 new)
        RDSMultiAZDisabledPolicy(),
        RDSBackupRetentionPolicy(),
        RDSDeletionProtectionPolicy(),
        RDSAutoMinorVersionUpgradePolicy(),
        RDSEnhancedMonitoringPolicy(),
        RDSPerformanceInsightsPolicy(),
        RDSDefaultPortPolicy(),

        # IAM (7 new)
        IAMAdminPolicyAttachedPolicy(),
        IAMInlineAdminPolicyPolicy(),
        IAMMFANotRequiredPolicy(),
        IAMAccessKeyRotationPolicy(),
        IAMRoleWildcardTrustPolicy(),
        IAMPasswordPolicyPolicy(),
        IAMGroupMembershipPolicy(),

        # Networking / VPC (6 new)
        VPCFlowLogsDisabledPolicy(),
        SecurityGroupSshOpenPolicy(),
        SecurityGroupRDPOpenPolicy(),
        SecurityGroupUnrestrictedEgressPolicy(),
        SubnetPublicIPOnLaunchPolicy(),
        NACLAllowAllPolicy(),

        # Docker (8 new)
        DockerLatestTagPolicy(),
        DockerAddInsteadOfCopyPolicy(),
        DockerHealthCheckMissingPolicy(),
        DockerSecretsInEnvPolicy(),
        DockerExposedPrivilegedPortPolicy(),
        DockerNoWorkdirPolicy(),
        DockerSecretsInArgPolicy(),
        DockerMultiStageMissingPolicy(),

        # Kubernetes (12 new)
        K8sReadOnlyRootFilesystemPolicy(),
        K8sAllowPrivilegeEscalationPolicy(),
        K8sRunAsRootPolicy(),
        K8sHostPIDPolicy(),
        K8sHostIPCPolicy(),
        K8sImagePullPolicyPolicy(),
        K8sLivenessProbePolicy(),
        K8sReadinessProbePolicy(),
        K8sDefaultNamespacePolicy(),
        K8sAutomountServiceAccountPolicy(),
        K8sCapabilitiesPolicy(),
        K8sResourceRequestsMissingPolicy(),

        # CloudTrail / Monitoring (8 new)
        CloudTrailDisabledPolicy(),
        CloudTrailLogValidationPolicy(),
        CloudTrailMultiRegionPolicy(),
        CloudWatchAlarmMissingPolicy(),
        GuardDutyDisabledPolicy(),
        SecurityHubDisabledPolicy(),
        ConfigServiceDisabledPolicy(),
        KMSKeyRotationPolicy(),

        # ELB / ALB / WAF / Route53 (7 new)
        ALBHTTPSOnlyPolicy(),
        ALBAccessLogsDisabledPolicy(),
        WAFMissingPolicy(),
        LBDeletionProtectionPolicy(),
        ALBTLSPolicyPolicy(),
        Route53DNSSECPolicy(),
        ELBCrossZoneLoadBalancingPolicy(),

        # Terraform General (5 new)
        TerraformBackendNotConfiguredPolicy(),
        TerraformProviderVersionPinnedPolicy(),
        TerraformOutputSensitivePolicy(),
        TerraformVariableDefaultSecretPolicy(),
        TerraformSensitiveVariableNotMarkedPolicy(),
        # EKS / Lambda / ECS
        EKSPublicEndpointPolicy(),
        EKSLoggingDisabledPolicy(),
        LambdaPublicAccessPolicy(),
        LambdaEnvSecretsPolicy(),
        LambdaReservedConcurrencyPolicy(),
        ECSTaskPrivilegedPolicy(),
        ECSTaskReadonlyRootPolicy(),

        # Messaging / Cache / DynamoDB
        SNSTopicEncryptionPolicy(),
        SQSQueueEncryptionPolicy(),
        DynamoDBEncryptionPolicy(),
        ElastiCacheEncryptionInTransitPolicy(),
        ElastiCacheEncryptionAtRestPolicy(),

        # ECR / Secrets / CloudFront
        ECRImageScanningPolicy(),
        ECRImageMutabilityPolicy(),
        SecretManagerRotationPolicy(),
        CloudFrontHTTPSPolicy(),
    ]