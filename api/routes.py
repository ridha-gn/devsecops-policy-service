from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from api.schemas import (
    AnalyzeRequest, AnalyzeResponse, Decision, Violation, Severity,
    FixRequest, FixResponse, FixDetail
)
from api.history import save_scan, get_history, get_stats
from api.report import generate_html_report
from engine.policy_engine import PolicyEngine
from engine.auto_fix import AutoFixer

router = APIRouter()
engine = PolicyEngine()
auto_fixer = AutoFixer()

SEV_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_code(request: AnalyzeRequest):
    try:
        result = engine.analyze(
            code_type=request.code_type.value,
            content=request.content,
            block_threshold=request.block_threshold.value,
            diff_only=request.diff_only,
        )

        threshold_level = SEV_ORDER.get(request.block_threshold.value, 1)

        violations_out = []
        for v in result.violations:
            violations_out.append(Violation(
                rule=v.rule_id,
                severity=Severity(v.severity.value),
                line=v.line_number,
                message=v.message,
                recommendation=v.recommendation,
            ))

        blocking = [
            v for v in violations_out
            if SEV_ORDER.get(v.severity.value, 0) >= threshold_level
        ]
        decision = Decision.BLOCK if blocking else Decision.ALLOW

        filename = request.filename or f"scan.{request.code_type.value}"

        # Save to SQLite
        save_scan(
            filename=filename,
            code_type=request.code_type.value,
            decision=decision.value,
            violations=[v.model_dump() for v in violations_out],
            scan_time_ms=result.scan_duration_ms or 0,
            block_threshold=request.block_threshold.value,
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


# ──────────────────────────────────────────────────────────────────────
#  AUTO-FIX ENDPOINT
# ──────────────────────────────────────────────────────────────────────

@router.post("/fix", response_model=FixResponse)
async def fix_code(request: FixRequest):
    """Automatically fix security violations in infrastructure code."""
    try:
        fix_result = auto_fixer.fix(
            code_type=request.code_type.value,
            content=request.content
        )

        fixes_out = []
        for f in fix_result.fixes_applied:
            fixes_out.append(FixDetail(
                rule_id=f.rule_id,
                line=f.line_number,
                description=f.description,
                original=f.original,
                fixed=f.fixed,
            ))

        diff = auto_fixer.generate_diff(
            fix_result.original_code,
            fix_result.fixed_code
        )

        return FixResponse(
            original_code=fix_result.original_code,
            fixed_code=fix_result.fixed_code,
            fixes_applied=fixes_out,
            total_fixes=fix_result.total_fixes,
            diff=diff,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ──────────────────────────────────────────────────────────────────────
#  REPORTS
# ──────────────────────────────────────────────────────────────────────

@router.get("/report/{filename}")
async def get_report(filename: str):
    history = get_history(limit=1)
    if not history:
        raise HTTPException(status_code=404, detail="No scan found")

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


@router.get("/report/{filename}/pdf")
async def get_report_pdf(filename: str):
    """Generate a downloadable PDF security report."""
    history = get_history(limit=1)
    if not history:
        raise HTTPException(status_code=404, detail="No scan found")

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
        pdf_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(html, dest=pdf_buffer)
        if pisa_status.err:
            raise HTTPException(status_code=500, detail="PDF generation failed")
        pdf_buffer.seek(0)
        return Response(
            content=pdf_buffer.read(),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=security-report-{filename}.pdf"
            }
        )
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="PDF export not available. Install: pip install xhtml2pdf"
        )


# ──────────────────────────────────────────────────────────────────────
#  HISTORY & METRICS
# ──────────────────────────────────────────────────────────────────────

@router.get("/history")
async def scan_history(limit: int = 50):
    return get_history(limit=limit)


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "policy-engine"}


@router.get("/metrics")
async def metrics():
    from api.metrics import get_metrics
    stats = get_stats()
    metrics_data = get_metrics()
    stats['top_violations'] = metrics_data.get('top_violations', [])
    stats['requests_by_type'] = metrics_data.get('requests_by_type', {})
    return stats


@router.get("/metrics/prometheus")
async def prometheus_metrics():
    """Prometheus-compatible metrics endpoint for Grafana scraping."""
    from api.prometheus import generate_prometheus_metrics
    return PlainTextResponse(
        content=generate_prometheus_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )
