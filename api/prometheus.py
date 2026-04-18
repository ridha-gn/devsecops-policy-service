"""
Prometheus-compatible metrics endpoint.

Exposes scan metrics in Prometheus text exposition format
so Grafana can scrape and visualize them.
"""

from api.history import get_stats, get_history
from api.metrics import get_metrics
import json


def generate_prometheus_metrics() -> str:
    """Generate metrics in Prometheus text exposition format."""
    stats = get_stats()
    extra = get_metrics()

    lines = []

    # ── Counters ──
    lines.append('# HELP devsecops_scans_total Total number of scans performed')
    lines.append('# TYPE devsecops_scans_total counter')
    lines.append(f'devsecops_scans_total {stats["total_requests"]}')
    lines.append('')

    lines.append('# HELP devsecops_blocks_total Total number of blocked scans')
    lines.append('# TYPE devsecops_blocks_total counter')
    lines.append(f'devsecops_blocks_total {stats["total_blocks"]}')
    lines.append('')

    lines.append('# HELP devsecops_allows_total Total number of allowed scans')
    lines.append('# TYPE devsecops_allows_total counter')
    lines.append(f'devsecops_allows_total {stats["total_allows"]}')
    lines.append('')

    # ── Gauges ──
    lines.append('# HELP devsecops_block_rate Block rate percentage')
    lines.append('# TYPE devsecops_block_rate gauge')
    lines.append(f'devsecops_block_rate {stats["block_rate_percent"]}')
    lines.append('')

    # ── Scans by code type ──
    lines.append('# HELP devsecops_scans_by_type Scans broken down by code type')
    lines.append('# TYPE devsecops_scans_by_type counter')
    for code_type, count in extra.get('requests_by_type', {}).items():
        lines.append(f'devsecops_scans_by_type{{code_type="{code_type}"}} {count}')
    lines.append('')

    # ── Top violations ──
    lines.append('# HELP devsecops_violation_count Count per violation rule')
    lines.append('# TYPE devsecops_violation_count counter')
    for v in extra.get('top_violations', []):
        rule = v['rule']
        count = v['count']
        lines.append(f'devsecops_violation_count{{rule="{rule}"}} {count}')
    lines.append('')

    # ── Scan duration (from recent scans) ──
    history = get_history(limit=100)
    if history:
        durations = [s['scan_time_ms'] for s in history if s.get('scan_time_ms')]
        if durations:
            avg_ms = sum(durations) / len(durations)
            min_ms = min(durations)
            max_ms = max(durations)

            lines.append('# HELP devsecops_scan_duration_ms Scan duration in milliseconds')
            lines.append('# TYPE devsecops_scan_duration_ms summary')
            lines.append(f'devsecops_scan_duration_ms_avg {avg_ms:.1f}')
            lines.append(f'devsecops_scan_duration_ms_min {min_ms}')
            lines.append(f'devsecops_scan_duration_ms_max {max_ms}')
            lines.append(f'devsecops_scan_duration_ms_count {len(durations)}')
            lines.append(f'devsecops_scan_duration_ms_sum {sum(durations)}')
            lines.append('')

    # ── Violations by severity (from recent scans) ──
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for scan in history:
        try:
            violations = json.loads(scan.get('violations_json', '[]'))
            for v in violations:
                sev = v.get('severity', 'LOW')
                if sev in sev_counts:
                    sev_counts[sev] += 1
        except Exception:
            pass

    lines.append('# HELP devsecops_violations_by_severity Total violations by severity')
    lines.append('# TYPE devsecops_violations_by_severity counter')
    for sev, count in sev_counts.items():
        lines.append(f'devsecops_violations_by_severity{{severity="{sev}"}} {count}')
    lines.append('')

    return '\n'.join(lines)
