from datetime import datetime
from typing import List


SEV_COLOR = {
    'CRITICAL': '#ff2d55',
    'HIGH':     '#ff6b35',
    'MEDIUM':   '#ffd166',
    'LOW':      '#06d6a0',
}

SEV_BG = {
    'CRITICAL': 'rgba(255,45,85,0.12)',
    'HIGH':     'rgba(255,107,53,0.12)',
    'MEDIUM':   'rgba(255,209,102,0.12)',
    'LOW':      'rgba(6,214,160,0.12)',
}


def generate_html_report(filename: str, code_type: str, decision: str,
                          violations: list, scan_time_ms: int,
                          block_threshold: str, explanation: str) -> str:

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    decision_color = '#ff2d55' if decision == 'BLOCK' else '#06d6a0'
    decision_bg    = 'rgba(255,45,85,0.1)' if decision == 'BLOCK' else 'rgba(6,214,160,0.1)'

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for v in violations:
        sev = v.get('severity', 'LOW')
        if sev in sev_counts:
            sev_counts[sev] += 1

    violations_html = ''
    for v in violations:
        sev   = v.get('severity', 'LOW')
        color = SEV_COLOR.get(sev, '#888')
        bg    = SEV_BG.get(sev, 'rgba(0,0,0,0.1)')
        line  = f"Line {v.get('line')}" if v.get('line') else ''
        violations_html += f'''
        <div class="violation" style="border-left:3px solid {color};background:{bg}">
            <div class="v-header">
                <span class="v-rule">{v.get("rule","")}</span>
                <span class="v-sev" style="color:{color}">{sev}</span>
                <span class="v-line">{line}</span>
            </div>
            <div class="v-msg">{v.get("message","")}</div>
            <div class="v-rec"><strong>Fix:</strong> {v.get("recommendation","")}</div>
        </div>'''

    if not violations_html:
        violations_html = '<div class="no-violations">No violations detected — code is compliant.</div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {filename}</title>
<style>
  @import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@700;800&display=swap");
  *{ box-sizing:border-box;margin:0;padding:0} 
  body{ background:#080c10;color:#c9d1d9;font-family:"JetBrains Mono",monospace;font-size:13px;padding:40px;min-height:100vh} 
  .report{ max-width:860px;margin:0 auto} 
  .header{ display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid #1c2433} 
  .logo{ font-family:"Syne",sans-serif;font-size:18px;font-weight:800;color:#fff;letter-spacing:.05em} 
  .logo span{ color:#00e5ff} 
  .meta{ text-align:right;font-size:11px;color:#4a5568;line-height:1.8} 
  .decision-box{ padding:20px 28px;border-radius:6px;border:1px solid;margin-bottom:28px;display:flex;align-items:center;justify-content:space-between} 
  .decision-label{ font-family:"Syne",sans-serif;font-size:28px;font-weight:800} 
  .decision-sub{ font-size:12px;color:#4a5568;margin-top:4px} 
  .stats{ display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px} 
  .stat{ background:#0d1117;border:1px solid #1c2433;border-radius:6px;padding:14px;text-align:center} 
  .stat-val{ font-family:"Syne",sans-serif;font-size:24px;font-weight:800;margin-bottom:4px} 
  .stat-label{ font-size:10px;color:#4a5568;text-transform:uppercase;letter-spacing:.1em} 
  .section-title{ font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:#4a5568;margin-bottom:12px} 
  .violation{ border-radius:4px;padding:14px;margin-bottom:10px} 
  .v-header{ display:flex;align-items:center;gap:10px;margin-bottom:8px} 
  .v-rule{ font-weight:600;font-size:13px;color:#fff} 
  .v-sev{ font-size:10px;font-weight:700;letter-spacing:.08em} 
  .v-line{ font-size:10px;color:#4a5568;margin-left:auto} 
  .v-msg{ font-size:12px;color:#c9d1d9;margin-bottom:6px;line-height:1.5} 
  .v-rec{ font-size:11px;color:#4a5568;line-height:1.5;padding:8px;background:rgba(255,255,255,.03);border-radius:3px} 
  .no-violations{ text-align:center;padding:40px;color:#06d6a0;font-size:14px} 
  .footer{ margin-top:32px;padding-top:16px;border-top:1px solid #1c2433;font-size:10px;color:#4a5568;text-align:center} 
  @media print{ body{ background:#fff;color:#000} } 
</style>
</head>
<body>
<div class="report">
  <div class="header">
    <div>
      <div class="logo">DEV<span>SEC</span>OPS · POLICY ENGINE</div>
      <div style="font-size:11px;color:#4a5568;margin-top:4px">Security Scan Report</div>
    </div>
    <div class="meta">
      <div>{now}</div>
      <div>{filename}</div>
      <div>Type: {code_type.upper()}</div>
      <div>Threshold: {block_threshold}</div>
      <div>Duration: {scan_time_ms}ms</div>
    </div>
  </div>

  <div class="decision-box" style="border-color:{decision_color};background:{decision_bg}">
    <div>
      <div class="decision-label" style="color:{decision_color}">{decision}</div>
      <div class="decision-sub">{explanation}</div>
    </div>
    <div style="font-size:48px;opacity:.3">{"🚫" if decision=="BLOCK" else "✅"}</div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-val" style="color:#ff2d55">{sev_counts["CRITICAL"]}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat">
      <div class="stat-val" style="color:#ff6b35">{sev_counts["HIGH"]}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat">
      <div class="stat-val" style="color:#ffd166">{sev_counts["MEDIUM"]}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat">
      <div class="stat-val" style="color:#06d6a0">{sev_counts["LOW"]}</div>
      <div class="stat-label">Low</div>
    </div>
  </div>

  <div class="section-title">Violations ({len(violations)} total)</div>
  {violations_html}

  <div class="footer">
    Generated by DevSecOps Policy Engine · {now} · {len(violations)} violations · {scan_time_ms}ms
  </div>
</div>
</body>
</html>'''
