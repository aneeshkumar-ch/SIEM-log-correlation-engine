import os
import uuid
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, File, Form, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

import config
import normalizer
import correlate
import collector
import sample_log_generator
import dashboard_service
from storage import get_es_client, initialize_indices, bulk_index_events, MockElasticsearch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="SIEM Log Correlation Engine - BCSSL Lab 07")

# Templates directory
templates_dir = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


def get_pipeline_state(es: Any) -> Dict[str, Any]:
    """Retrieves cluster connectivity and event/alert document counts."""
    initialize_indices(es)
    is_mock = isinstance(es, MockElasticsearch)
    try:
        es_connected = es.ping()
        mode_label = "Mock ES Mode" if is_mock else "Connected (Elasticsearch 8.13)"
    except Exception:
        es_connected = False
        mode_label = "Disconnected"

    try:
        events_cnt = es.count(index=config.INDEX_EVENTS)["count"]
    except Exception:
        events_cnt = 0

    try:
        alerts_cnt = es.count(index=config.INDEX_ALERTS)["count"]
    except Exception:
        alerts_cnt = 0

    # Fetch alerts & calculate SOC Triage Board analytics
    alerts = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    ip_counter = {}
    suspicious_hosts = []

    try:
        res = es.search(
            index=config.INDEX_ALERTS,
            query={"match_all": {}},
            sort=[{"created_at": {"order": "desc"}}],
            size=100
        )
        for hit in res.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            src["_id"] = hit.get("_id")
            alerts.append(src)

            # Triage metrics
            s = str(src.get("severity", "")).lower()
            if s in sev_counts:
                sev_counts[s] += 1

            ip = src.get("src_ip")
            if ip:
                ip_counter[ip] = ip_counter.get(ip, 0) + 1

            if src.get("rule_name") == "Post-Logon Suspicious Execution":
                suspicious_hosts.append(src)

    except Exception as e:
        logger.warning("Could not fetch alerts: %s", e)

    top_ips = sorted([{"ip": k, "count": v} for k, v in ip_counter.items()], key=lambda x: x["count"], reverse=True)[:5]

    return {
        "es_connected": es_connected,
        "es_mode": mode_label,
        "events_count": events_cnt,
        "alerts_count": alerts_cnt,
        "alerts": alerts,
        "sev_counts": sev_counts,
        "top_ips": top_ips,
        "suspicious_hosts": suspicious_hosts,
        "kibana_url": config.KIBANA_HOST
    }


@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request, flash: Optional[str] = None, flash_type: Optional[str] = None):
    es = get_es_client()
    state = get_pipeline_state(es)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "flash_message": flash,
            "flash_type": flash_type,
            **state
        }
    )


@app.post("/upload", response_class=HTMLResponse)
async def handle_upload(
    request: Request,
    file: UploadFile = File(...),
    source_type: str = Form(...)
):
    es = get_es_client()
    initialize_indices(es)

    # 1. Validate file extension
    orig_name = file.filename or ""
    suffix = Path(orig_name).suffix.lower()
    if suffix not in config.ALLOWED_EXTENSIONS:
        state = get_pipeline_state(es)
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "flash_message": f"Rejected: File extension '{suffix}' not allowed. Must be one of: {', '.join(config.ALLOWED_EXTENSIONS)}",
                "flash_type": "error",
                **state
            },
            status_code=400
        )

    # 2. Read content safely with size limit enforcement (20MB)
    try:
        raw_bytes = await file.read(config.MAX_UPLOAD_SIZE_BYTES + 1)
        if len(raw_bytes) > config.MAX_UPLOAD_SIZE_BYTES:
            state = get_pipeline_state(es)
            return templates.TemplateResponse(
                request=request,
                name="index.html",
                context={
                    "flash_message": f"Rejected: Upload exceeds maximum allowed limit of {config.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB.",
                    "flash_type": "error",
                    **state
                },
                status_code=413
            )
    except Exception as e:
        state = get_pipeline_state(es)
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "flash_message": f"File read error: {e}",
                "flash_type": "error",
                **state
            },
            status_code=500
        )

    # 3. Store file under a generated UUID in ./uploads (never use original filename as path)
    gen_filename = f"{uuid.uuid4().hex}{suffix}"
    saved_path = config.UPLOADS_DIR / gen_filename
    with open(saved_path, "wb") as f_out:
        f_out.write(raw_bytes)
    logger.info("Saved upload to %s", saved_path)

    # 4. Decode content (treat strictly as passive data, never evaluate or execute)
    try:
        content_str = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = raw_bytes.decode("latin-1", errors="replace")

    # 5. Parse and normalize
    try:
        events, skipped = normalizer.normalize_content(content_str, source_type)
    except Exception as e:
        state = get_pipeline_state(es)
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "flash_message": f"Parsing failure for source {source_type}: {e}",
                "flash_type": "error",
                **state
            },
            status_code=400
        )

    # 6. Bulk index into normalized-events with deterministic IDs
    indexed_count = bulk_index_events(es, events, config.INDEX_EVENTS)
    try:
        es.indices.refresh(index=config.INDEX_EVENTS)
    except Exception:
        pass
    logger.info("Successfully indexed %d normalized events into %s", indexed_count, config.INDEX_EVENTS)

    # 7. Run correlation rules
    new_alerts = correlate.run_correlation(es)
    try:
        es.indices.refresh(index=config.INDEX_ALERTS)
    except Exception:
        pass

    state = get_pipeline_state(es)
    upload_summary = {
        "events_parsed": len(events),
        "skipped": skipped,
        "alerts": new_alerts,
        "saved_as": gen_filename
    }

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "flash_message": f"Ingestion complete: {len(events)} event(s) parsed, {len(skipped)} line(s) skipped, {len(new_alerts)} alert(s) evaluated.",
            "flash_type": "success",
            "upload_summary": upload_summary,
            **state
        }
    )


@app.post("/correlate", response_class=HTMLResponse)
async def trigger_correlation(request: Request):
    es = get_es_client()
    alerts = correlate.run_correlation(es)
    try:
        es.indices.refresh(index=config.INDEX_ALERTS)
    except Exception:
        pass
    state = get_pipeline_state(es)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "flash_message": f"Correlation run completed: {len(alerts)} alert(s) active in {config.INDEX_ALERTS}.",
            "flash_type": "info",
            **state
        }
    )


@app.post("/clear", response_class=HTMLResponse)
async def clear_pipeline_data(request: Request):
    es = get_es_client()
    try:
        if es.indices.exists(index=config.INDEX_EVENTS):
            es.indices.delete(index=config.INDEX_EVENTS, ignore_unavailable=True)
        if es.indices.exists(index=config.INDEX_ALERTS):
            es.indices.delete(index=config.INDEX_ALERTS, ignore_unavailable=True)
        initialize_indices(es)
        try:
            es.indices.refresh(index=config.INDEX_EVENTS)
            es.indices.refresh(index=config.INDEX_ALERTS)
        except Exception:
            pass
        msg = "Pipeline data successfully cleared. Both indices reset."
        msg_type = "success"
    except Exception as e:
        msg = f"Failed to reset indices: {e}"
        msg_type = "error"

    state = get_pipeline_state(es)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "flash_message": msg,
            "flash_type": msg_type,
            **state
        }
    )


@app.get("/api/status")
async def api_status():
    es = get_es_client()
    state = get_pipeline_state(es)
    return {
        "connected": state["es_connected"],
        "mode": state["es_mode"],
        "events_count": state["events_count"],
        "alerts_count": state["alerts_count"],
        "kibana_url": state["kibana_url"]
    }


@app.get("/api/alerts")
async def api_alerts():
    es = get_es_client()
    state = get_pipeline_state(es)
    return JSONResponse(content={"alerts": state["alerts"]})


@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request, events_index: Optional[str] = None, alerts_index: Optional[str] = None):
    return templates.TemplateResponse(
        request=request,
        name="analyst_dashboard.html",
        context={}
    )


@app.get("/api/dashboard-data")
async def api_dashboard_data(events_index: Optional[str] = None, alerts_index: Optional[str] = None):
    es = get_es_client()
    ev_idx = events_index or config.INDEX_EVENTS
    alt_idx = alerts_index or config.INDEX_ALERTS
    data = dashboard_service.get_dashboard_analytics(es, events_index=ev_idx, alerts_index=alt_idx)
    return JSONResponse(content=data)


@app.get("/investigation", response_class=HTMLResponse)
async def get_investigation(
    request: Request,
    scenario: str = "scenario_1",
    flash: Optional[str] = None,
    flash_type: Optional[str] = None
):
    findings_file = config.INVESTIGATIONS_DIR / f"{scenario}_findings.json"
    saved = {}
    if findings_file.exists():
        try:
            saved = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    return templates.TemplateResponse(
        request=request,
        name="investigation.html",
        context={
            "kibana_url": config.KIBANA_HOST,
            "current_scenario": scenario,
            "saved_findings": saved,
            "flash_message": flash,
            "flash_type": flash_type
        }
    )


@app.post("/investigation/save", response_class=HTMLResponse)
async def save_investigation(
    request: Request,
    scenario_key: str = Form(...),
    analyst_name: str = Form(...),
    verdict: str = Form(...),
    impacted_hosts: str = Form(""),
    threat_ip: str = Form(""),
    mitre_technique: str = Form(""),
    timeline_summary: str = Form(""),
    evidence_ids: str = Form(""),
    recommendations: str = Form("")
):
    findings_data = {
        "scenario_key": scenario_key,
        "analyst_name": analyst_name,
        "verdict": verdict,
        "impacted_hosts": impacted_hosts,
        "threat_ip": threat_ip,
        "mitre_technique": mitre_technique,
        "timeline_summary": timeline_summary,
        "evidence_ids": evidence_ids,
        "recommendations": recommendations,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    findings_file = config.INVESTIGATIONS_DIR / f"{scenario_key}_findings.json"
    findings_file.write_text(json.dumps(findings_data, indent=2), encoding="utf-8")

    return templates.TemplateResponse(
        request=request,
        name="investigation.html",
        context={
            "kibana_url": config.KIBANA_HOST,
            "current_scenario": scenario_key,
            "saved_findings": findings_data,
            "flash_message": f"Findings for {scenario_key.replace('_', ' ').title()} successfully recorded to {findings_file.name}.",
            "flash_type": "success"
        }
    )


@app.get("/investigation/export/{scenario_key}")
async def export_investigation(scenario_key: str):
    findings_file = config.INVESTIGATIONS_DIR / f"{scenario_key}_findings.json"
    if not findings_file.exists():
        data = {
            "scenario_key": scenario_key,
            "analyst_name": "SOC Analyst",
            "verdict": "Under Investigation",
            "impacted_hosts": "N/A",
            "threat_ip": "N/A",
            "mitre_technique": "N/A",
            "timeline_summary": "Pending investigation notes.",
            "evidence_ids": "None documented yet.",
            "recommendations": "Conduct telemetry analysis.",
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    else:
        data = json.loads(findings_file.read_text(encoding="utf-8"))

    md = f"""# SOC Incident Investigation Report: {scenario_key.upper()}
**Investigator / Analyst:** {data.get('analyst_name', 'Analyst')}
**Date / Timestamp:** {data.get('updated_at', 'N/A')}
**Incident Verdict:** {data.get('verdict', 'N/A')}
**MITRE ATT&CK Technique:** {data.get('mitre_technique', 'N/A')}

---

## 1. Executive Summary & Scope
- **Impacted Host(s):** `{data.get('impacted_hosts', 'N/A')}`
- **Identified Threat IP(s):** `{data.get('threat_ip', 'N/A')}`

## 2. Chronological Timeline Analysis
{data.get('timeline_summary', 'No timeline documented.')}

## 3. Correlated Telemetry & Evidence Event IDs
The following deterministic SHA-256 event IDs were isolated from the `security-events` index:
```
{data.get('evidence_ids', 'None')}
```

## 4. Remediation & Hardening Recommendations
{data.get('recommendations', 'No recommendations provided.')}

---
*Generated by SIEM Log Correlation Engine (BCSSL Lab 07)*
"""
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={scenario_key}_report.md"}
    )


@app.post("/generate-samples", response_class=HTMLResponse)
async def generate_training_dataset(request: Request):
    es = get_es_client()
    initialize_indices(es)
    sample_files = sample_log_generator.generate_sample_logs()

    total_parsed = 0
    for stype, fpath in [("windows_sysmon", sample_files["windows"]),
                         ("linux_auditd", sample_files["linux"]),
                         ("network_firewall", sample_files["network"])]:
        res = collector.collect_file(Path(fpath), source_type=stype, es=es)
        total_parsed += res["events_parsed"]

    alerts = correlate.run_correlation(es)
    state = get_pipeline_state(es)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "flash_message": f"Training dataset generated and ingested: {total_parsed} events indexed across Windows, Linux, and Network logs. {len(alerts)} alerts active.",
            "flash_type": "success",
            **state
        }
    )


if __name__ == "__main__":
    import uvicorn
    # Bind exclusively to localhost / 127.0.0.1
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
