"""Report generation (JSON + HTML)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

from .analyzer import AnalysisResult


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>APK Analysis Report – {{ result.package_name }}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --danger: #f87171;
      --ok: #4ade80;
      --border: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 1.8rem; margin-bottom: 0.3rem; color: var(--accent); }
    h2 {
      font-size: 1.25rem;
      margin: 2rem 0 0.8rem;
      padding-bottom: 0.4rem;
      border-bottom: 1px solid var(--border);
      color: var(--accent);
    }
    .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem 1.3rem;
    }
    .card .label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .card .value { font-size: 1.15rem; font-weight: 600; margin-top: 0.25rem; word-break: break-all; }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-danger { background: #7f1d1d; color: #fecaca; }
    .badge-ok { background: #14532d; color: #bbf7d0; }
    .badge-warn { background: #713f12; color: #fde68a; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th, td {
      text-align: left;
      padding: 0.55rem 0.8rem;
      border-bottom: 1px solid var(--border);
    }
    th { color: var(--muted); font-weight: 500; }
    tr:hover td { background: rgba(56, 189, 248, 0.05); }
    .secret { color: var(--danger); font-family: monospace; font-size: 0.85rem; }
    .exported { color: var(--danger); }
    ul { list-style: none; }
    ul li { padding: 0.25rem 0; font-family: monospace; font-size: 0.88rem; }
    footer {
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 0.85rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Android APK Analysis Report</h1>
    <p class="meta">
      Generated: {{ generated_at }} · Tool: Android RE Toolkit v1.0
    </p>

    <h2>Basic Information</h2>
    <div class="grid">
      <div class="card"><div class="label">Package</div><div class="value">{{ result.package_name }}</div></div>
      <div class="card"><div class="label">App Name</div><div class="value">{{ result.app_name or '—' }}</div></div>
      <div class="card"><div class="label">Version</div><div class="value">{{ result.version_name }} ({{ result.version_code }})</div></div>
      <div class="card"><div class="label">Min / Target SDK</div><div class="value">{{ result.min_sdk }} / {{ result.target_sdk }}</div></div>
      <div class="card"><div class="label">File Size</div><div class="value">{{ (result.size_bytes / 1024 / 1024) | round(2) }} MB</div></div>
      <div class="card"><div class="label">SHA256</div><div class="value" style="font-size:0.75rem">{{ result.sha256 }}</div></div>
    </div>

    <h2>Security Flags</h2>
    <div class="grid">
      <div class="card">
        <div class="label">Debuggable</div>
        <div class="value">
          {% if result.is_debuggable %}
            <span class="badge badge-danger">YES</span>
          {% else %}
            <span class="badge badge-ok">NO</span>
          {% endif %}
        </div>
      </div>
      <div class="card">
        <div class="label">Dangerous Permissions</div>
        <div class="value">{{ result.dangerous_permissions | length }}</div>
      </div>
      <div class="card">
        <div class="label">Exported Components</div>
        <div class="value">{{ result.exported_components | length }}</div>
      </div>
      <div class="card">
        <div class="label">Potential Secrets</div>
        <div class="value">{{ result.secrets | length }}</div>
      </div>
    </div>

    <h2>Permissions ({{ result.permissions | length }})</h2>
    <div class="card">
      <ul>
        {% for p in result.permissions %}
          <li>
            {% if p in result.dangerous_permissions %}
              <span class="badge badge-danger">DANGEROUS</span>
            {% endif %}
            {{ p }}
          </li>
        {% else %}
          <li>None found</li>
        {% endfor %}
      </ul>
    </div>

    <h2>Components</h2>
    <div class="card">
      <p><strong>Activities:</strong> {{ result.activities | length }}
         (Exported: {{ result.activities | selectattr('exported') | list | length }})</p>
      <p><strong>Services:</strong> {{ result.services | length }}</p>
      <p><strong>Receivers:</strong> {{ result.receivers | length }}</p>
      <p><strong>Providers:</strong> {{ result.providers | length }}</p>

      {% if result.exported_components %}
      <h3 style="margin-top:1rem;color:var(--danger)">Exported Components</h3>
      <ul>
        {% for c in result.exported_components %}
          <li class="exported">{{ c }}</li>
        {% endfor %}
      </ul>
      {% endif %}
    </div>

    <h2>Code Statistics</h2>
    <div class="grid">
      <div class="card"><div class="label">DEX Files</div><div class="value">{{ result.dex_count }}</div></div>
      <div class="card"><div class="label">Classes</div><div class="value">{{ result.class_count }}</div></div>
      <div class="card"><div class="label">Methods</div><div class="value">{{ result.method_count }}</div></div>
      <div class="card"><div class="label">Native Libs</div><div class="value">{{ result.native_libs | length }}</div></div>
    </div>

    {% if result.native_libs %}
    <div class="card" style="margin-top:1rem">
      <ul>
        {% for lib in result.native_libs %}
          <li>{{ lib }}</li>
        {% endfor %}
      </ul>
    </div>
    {% endif %}

    {% if result.secrets %}
    <h2>Potential Secrets / Interesting Findings</h2>
    <div class="card">
      <table>
        <thead>
          <tr><th>Type</th><th>Value</th></tr>
        </thead>
        <tbody>
          {% for s in result.secrets %}
          <tr>
            <td>{{ s.type }}</td>
            <td class="secret">{{ s.value }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    {% if result.certificate_info %}
    <h2>Signing Certificate</h2>
    <div class="card">
      <p><strong>Subject:</strong> {{ result.certificate_info.subject }}</p>
      <p><strong>Issuer:</strong> {{ result.certificate_info.issuer }}</p>
      <p><strong>SHA256:</strong> <code>{{ result.certificate_info.sha256 }}</code></p>
    </div>
    {% endif %}

    <footer>
      Generated by <strong>Android RE Toolkit</strong> · For legitimate security research only
    </footer>
  </div>
</body>
</html>
"""


def generate_json(result: AnalysisResult, output_path: str | Path) -> Path:
    """Write JSON report."""
    path = Path(output_path)
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "android-re-toolkit",
        "version": "1.0.0",
        "result": result.to_dict(),
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def generate_html(result: AnalysisResult, output_path: str | Path) -> Path:
    """Write HTML report."""
    path = Path(output_path)
    template = Template(HTML_TEMPLATE)
    html = template.render(
        result=result,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    path.write_text(html, encoding="utf-8")
    return path
