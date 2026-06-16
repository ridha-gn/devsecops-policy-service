from typing import List, Dict, Any, Optional
from models.code_structure import NormalizedCode
from models.decision import PolicyDecision, PolicyViolation
from engine.parser import get_parser
from engine.normalizer import Normalizer
from engine.policies.security_policies import get_all_policies
import time
import logging
import re

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def parse_diff_lines(diff: str) -> set:
    """Extract line numbers added/changed in a unified diff."""
    changed_lines = set()
    current_line = 0
    for line in diff.splitlines():
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            if match:
                current_line = int(match.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            changed_lines.add(current_line)
        elif not line.startswith("-"):
            current_line += 1
    return changed_lines


class PolicyEngine:

    def __init__(self):
        self.normalizer = Normalizer()
        self.policies = get_all_policies()

    def analyze(
        self,
        code_type: str,
        content: str,
        block_threshold: str = "LOW",
        diff_only: Optional[str] = None,
    ) -> PolicyDecision:

        start_time = time.time()
        logger.info(
            f"Starting analysis for {code_type} code ({len(content)} characters)"
        )

        try:
            parser = get_parser(code_type)
            parsed_data = parser.parse(content)
            logger.info(f"Successfully parsed {code_type} code")

            if code_type == "terraform":
                extracted_resources = parser.extract_resources(parsed_data)
                logger.info(f"Extracted {len(extracted_resources)} resources")
                normalized_code = self.normalizer.normalize(
                    code_type, parsed_data, extracted_resources
                )
            elif code_type == "yaml":
                normalized_code = self.normalizer.normalize(
                    code_type, parsed_data, parser=parser
                )
            else:
                normalized_code = self.normalizer.normalize(code_type, parsed_data)

            all_violations = []
            for policy in self.policies:
                violations = policy.check(normalized_code)
                if violations:
                    logger.info(
                        f"Policy {policy.rule_id} found {len(violations)} violations"
                    )
                all_violations.extend(violations)

            if diff_only:
                changed_lines = parse_diff_lines(diff_only)
                if changed_lines:
                    all_violations = [
                        v
                        for v in all_violations
                        if v.line_number is None or v.line_number in changed_lines
                    ]
                    logger.info(
                        f"Diff filter applied — {len(changed_lines)} changed lines, {len(all_violations)} violations remain"
                    )

            threshold_level = SEV_ORDER.get(block_threshold.upper(), 1)
            blocking_violations = [
                v
                for v in all_violations
                if SEV_ORDER.get(v.severity.value, 0) >= threshold_level
            ]

            allow = len(blocking_violations) == 0

            if allow:
                if all_violations:
                    summary = f"ALLOW: {len(all_violations)} violation(s) below threshold ({block_threshold}). No blocking issues found."
                else:
                    summary = (
                        "All security checks passed. Code is compliant with policies."
                    )
                logger.info("Analysis result: ALLOW")
            else:
                critical = sum(
                    1 for v in blocking_violations if v.severity.value == "CRITICAL"
                )
                high = sum(1 for v in blocking_violations if v.severity.value == "HIGH")
                if critical > 0:
                    summary = f"CRITICAL: Found {critical} critical and {high} high severity violations. Immediate action required."
                elif high > 0:
                    summary = f"Found {high} high severity violations. Fix required before deployment."
                else:
                    summary = f"Found {len(blocking_violations)} policy violations. Review recommended."
                logger.warning(
                    f"Analysis result: BLOCK ({len(blocking_violations)} violations)"
                )

            scan_duration = int((time.time() - start_time) * 1000)
            logger.info(f"Analysis completed in {scan_duration}ms")

            return PolicyDecision(
                allow=allow,
                violations=all_violations,
                summary=summary,
                scan_duration_ms=scan_duration,
            )

        except Exception as e:
            logger.error(f"Policy analysis failed: {str(e)}", exc_info=True)
            raise Exception(f"Policy analysis failed: {str(e)}")
