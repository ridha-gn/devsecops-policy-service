from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from api.schemas import (
    AnalyzeRequest, AnalyzeResponse, Decision, Violation, Severity,
    FixRequest, FixResponse, FixDetail,
)
from api.history import save_scan, get_history, get_stats
from api.report import generate_html_report
from api.auth import UserRole, require_roles, get_current_user
from engine.policy_engine import PolicyEngine
from engine.auto_fix import AutoFixer

router = APIRouter()
engine = PolicyEngine()
auto_fixer = AutoFixer()

SEV_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}

# ── All roles that can log in ─────────────────────────────────────────────────
ALL_ROLES = (
    UserRole.DEVELOPER,
    UserRole.DEVOPS_ENGINEER,
    UserRole.SECURITY_OFFICER,
    UserRole.SUPER_ADMIN,
)


# ── ANALYZE ───────────────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["🔍 Policy Engine"],
    summary="Scan infrastructure code for security violations",
)
async def analyze_code(
    request: AnalyzeRequest,
    current_user: dict = Depends(require_roles(*ALL_ROLES)),
):
    """
    Analyze Terraform, Dockerfile, or YAML code against 103 security policies.
    **All authenticated roles** may use this endpoint.
    """
    try:
        result = engine.analyze(
            code_type=request.code_type.value,
            content=request.content,
            block_threshold=request.block_threshold.value,
            diff_only=request.diff_only,
        )

        threshold_level = SEV_ORDER.get(request.block_threshold.value, 1)

        violations_out = [
            Violation(
                rule=v.rule_id,
                severity=Severity(v.severity.value),
                line=v.line_number,
                message=v.message,
                recommendation=v.recommendation,
            )
            for v in result.violations
        ]

        blocking = [
            v for v in violations_out
            if SEV_ORDER.get(v.severity.value, 0) >= threshold_level
        ]
        decision = Decision.BLOCK if blocking else Decision.ALLOW

        filename = request.filename or f"scan.{request.code_type.value}"

        save_scan(
            filename=filename,
            code_type=request.code_type.value,
            decision=decision.value,
            violations=[v.model_dump() for v in violations_out],
            scan_time_ms=result.scan_duration_ms or 0,
            block_threshold=request.block_threshold.value,
            scanned_by=current_user["username"],
        )

        return AnalyzeResponse(
            decision=decision,
            violations=violations_out,
            explanation=result.summary,
            scan_time_ms=result.scan_duration_ms,
            filename=filename,
            block_threshold=request.block_threshold.value,
            report_url=f"/report/{filename}",
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── AUTO-FIX ──────────────────────────────────────────────────────────────────

@router.post(
    "/fix",
    response_model=FixResponse,
    tags=["🔧 Auto-Fix"],
    summary="Automatically remediate security violations",
)
async def fix_code(
    request: FixRequest,
    _: dict = Depends(require_roles(UserRole.DEVOPS_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Automatically fix security violations in infrastructure code.
    **DevOps Engineer** and **Super Admin** only.
    """
    try:
        fix_result = auto_fixer.fix(
            code_type=request.code_type.value,
            content=request.content,
        )

        fixes_out = [
            FixDetail(
                rule_id=f.rule_id,
                line=f.line_number,
                description=f.description,
                original=f.original,
                fixed=f.fixed,
            )
            for f in fix_result.fixes_applied
        ]

        diff = auto_fixer.generate_diff(fix_result.original_code, fix_result.fixed_code)

        return FixResponse(
            original_code=fix_result.original_code,
            fixed_code=fix_result.fixed_code,
            fixes_applied=fixes_out,
            total_fixes=fix_result.total_fixes,
            diff=diff,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── REPORTS ───────────────────────────────────────────────────────────────────

@router.get(
    "/report/{filename}",
    tags=["📄 Reports"],
    summary="View HTML security report",
)
async def get_report(
    filename: str,
    _: dict = Depends(require_roles(*ALL_ROLES)),
):
    """View the HTML security report for a scan. **All roles** may access."""
    history = get_history(limit=1)
    if not history:
        raise HTTPException(status_code=404, detail="No scan found.")

    import json
    last = history[0]
    violations = json.loads(last['violations_json'])

    html = generate_html_report(
        filename=last['filename'],
        code_type=last['code_type'],
        decision=last['decision'],
        violations=violations,
        scan_time_ms=last['scan_time_ms'],
        block_threshold=last['block_threshold'],
        explanation=f"{last['violations_count']} violation(s) found",
    )
    return HTMLResponse(content=html)


@router.get(
    "/report/{filename}/pdf",
    tags=["📄 Reports"],
    summary="Download PDF security report",
)
async def get_report_pdf(
    filename: str,
    _: dict = Depends(require_roles(
        UserRole.DEVOPS_ENGINEER,
        UserRole.SECURITY_OFFICER,
        UserRole.SUPER_ADMIN,
    )),
):
    """
    Download a PDF security report.
    **DevOps Engineer**, **Security Officer**, and **Super Admin** only.
    """
    history = get_history(limit=1)
    if not history:
        raise HTTPException(status_code=404, detail="No scan found.")

    import json
    last = history[0]
    violations = json.loads(last['violations_json'])

    html = generate_html_report(
        filename=last['filename'],
        code_type=last['code_type'],
        decision=last['decision'],
        violations=violations,
        scan_time_ms=last['scan_time_ms'],
        block_threshold=last['block_threshold'],
        explanation=f"{last['violations_count']} violation(s) found",
    )

    try:
        from xhtml2pdf import pisa
        import io
        buf = io.BytesIO()
        pisa_status = pisa.CreatePDF(html, dest=buf)
        if pisa_status.err:
            raise HTTPException(status_code=500, detail="PDF generation failed.")
        buf.seek(0)
        return Response(
            content=buf.read(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security-report-{filename}.pdf"},
        )
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="PDF export not available. Install: pip install xhtml2pdf",
        )


# ── HISTORY & METRICS ─────────────────────────────────────────────────────────

@router.get(
    "/history",
    tags=["📊 Metrics & History"],
    summary="View scan history",
)
async def scan_history(
    limit: int = 50,
    current_user: dict = Depends(require_roles(*ALL_ROLES)),
):
    """
    Returns scan history.
    - **Developer**: sees only their own scans.
    - **DevOps / Security Officer / Super Admin**: sees all scans.
    """
    if current_user["role"] == UserRole.DEVELOPER:
        return get_history(limit=limit, username=current_user["username"])
    return get_history(limit=limit)


@router.get("/health", tags=["⚙️ System"])
async def health():
    """Public health check — no authentication required."""
    return {"status": "healthy", "service": "policy-engine"}


@router.get(
    "/metrics",
    tags=["📊 Metrics & History"],
    summary="View JSON metrics dashboard",
)
async def metrics(
    _: dict = Depends(require_roles(
        UserRole.DEVOPS_ENGINEER,
        UserRole.SECURITY_OFFICER,
        UserRole.SUPER_ADMIN,
    )),
):
    """
    Returns JSON metrics summary.
    **DevOps Engineer**, **Security Officer**, and **Super Admin** only.
    """
    from api.metrics import get_metrics
    stats = get_stats()
    metrics_data = get_metrics()
    stats['top_violations'] = metrics_data.get('top_violations', [])
    stats['requests_by_type'] = metrics_data.get('requests_by_type', {})
    return stats


@router.get(
    "/metrics/prometheus",
    tags=["📊 Metrics & History"],
    summary="Prometheus-format metrics for Grafana",
)
async def prometheus_metrics(
    _: dict = Depends(require_roles(
        UserRole.SECURITY_OFFICER,
        UserRole.SUPER_ADMIN,
    )),
):
    """
    Prometheus-compatible metrics endpoint.
    **Security Officer** and **Super Admin** only.
    """
    from api.prometheus import generate_prometheus_metrics
    return PlainTextResponse(
        content=generate_prometheus_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
