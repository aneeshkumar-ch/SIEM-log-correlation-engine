import os
import uuid
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request, File, Form, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse
from starlette.background import BackgroundTask

import config
import normalizer
import correlate
import collector
import sample_log_generator
import dashboard_service
from storage import get_es_client, initialize_indices, bulk_index_events, MockElasticsearch
from pipeline_manager import pipeline_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan handler to start and stop background collector, correlation scheduler, and Kibana proxy client."""
    app.state.proxy_client = httpx.AsyncClient(
        base_url=config.KIBANA_HOST,
        timeout=httpx.Timeout(60.0, connect=10.0),
        follow_redirects=False,
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
    )
    await pipeline_manager.start()
    try:
        yield
    finally:
        await pipeline_manager.stop()
        if hasattr(app.state, "proxy_client"):
            await app.state.proxy_client.aclose()


app = FastAPI(title="SIEM Log Correlation Engine - BCSSL Lab 07", lifespan=lifespan)

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
        "kibana_url": config.KIBANA_EXTERNAL_URL
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
    pipeline_manager.record_event_ingest(count=indexed_count)
    logger.info("Successfully indexed %d normalized events into %s", indexed_count, config.INDEX_EVENTS)

    # 7. Run correlation rules
    new_alerts = correlate.run_correlation(es)
    try:
        es.indices.refresh(index=config.INDEX_ALERTS)
    except Exception:
        pass
    pipeline_manager.record_correlation_run(new_alerts)

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
    pipeline_manager.record_correlation_run(alerts)
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
        pipeline_manager.reset_state()
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
        "kibana_url": state.get("kibana_url") or config.KIBANA_HOST
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


@app.get("/api/pipeline-health")
async def api_pipeline_health():
    """Returns background collector, correlation scheduler, and Elasticsearch health."""
    es = get_es_client()
    return JSONResponse(content=pipeline_manager.get_health(es))


KIBANA_REFRESH_G = "_g=(refreshInterval:(pause:!f,value:2000),time:(from:now-7d,to:now%2B1d))"


@app.get("/open/soc")
async def open_soc_dashboard():
    """Redirects to Kibana SOC Triage Board with forced 2s auto-refresh global state."""
    base = config.KIBANA_EXTERNAL_URL
    return RedirectResponse(f"{base}/app/dashboards#/view/soc-triage-board-dashboard?{KIBANA_REFRESH_G}")


@app.get("/open/alerts")
async def open_alerts_dashboard():
    """Redirects to Kibana Alerts Dashboard with forced 2s auto-refresh global state."""
    base = config.KIBANA_EXTERNAL_URL
    return RedirectResponse(f"{base}/app/dashboards#/view/alerts-dashboard?{KIBANA_REFRESH_G}")


@app.get("/open/timeline")
async def open_timeline_dashboard():
    """Redirects to Kibana Timeline Analysis Dashboard with forced 2s auto-refresh global state."""
    base = config.KIBANA_EXTERNAL_URL
    return RedirectResponse(f"{base}/app/dashboards#/view/timeline-analysis-dashboard?{KIBANA_REFRESH_G}")


@app.get("/open/discover")
@app.get("/open/events")
async def open_discover_search():
    """Redirects to Kibana Discover Events search with forced 2s auto-refresh global state."""
    base = config.KIBANA_EXTERNAL_URL
    return RedirectResponse(f"{base}/app/discover#/view/events-search?{KIBANA_REFRESH_G}")


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
            "kibana_url": config.KIBANA_EXTERNAL_URL,
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
            "kibana_url": config.KIBANA_EXTERNAL_URL,
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

    if total_parsed > 0:
        pipeline_manager.record_event_ingest(total_parsed)

    alerts = correlate.run_correlation(es)
    try:
        es.indices.refresh(index=config.INDEX_ALERTS)
    except Exception:
        pass
    pipeline_manager.record_correlation_run(alerts)
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



@app.get("/kibana")
@app.get("/kibana/")
async def open_kibana_root():
    """Redirect /kibana and /kibana/ to the SOC Triage Board."""
    return RedirectResponse("/open/soc")


@app.api_route("/kibana/{subpath:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def open_kibana_subpath(request: Request, subpath: str):
    """Strip /kibana prefix and redirect to root-relative path."""
    clean_sub = subpath.strip("/")
    if not clean_sub:
        return RedirectResponse("/open/soc")
    query_str = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(f"/{clean_sub}{query_str}")


HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade"
}


async def forward_to_kibana(request: Request, path: str):
    target_path = "/" + path
    if request.url.query:
        target_path += "?" + request.url.query

    req_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "host"
    }
    req_headers["host"] = "127.0.0.1:5601"
    if "kbn-xsrf" not in req_headers:
        req_headers["kbn-xsrf"] = "true"

    body = await request.body()

    client = getattr(request.app.state, "proxy_client", None)
    should_close = False
    if client is None or client.is_closed:
        client = httpx.AsyncClient(base_url=config.KIBANA_HOST, timeout=60.0, follow_redirects=False)
        should_close = True

    try:
        req = client.build_request(method=request.method, url=target_path, headers=req_headers, content=body)
        resp = await client.send(req, stream=True)
    except httpx.ConnectError:
        if should_close:
            await client.aclose()
        return Response(content="Kibana is unreachable at 127.0.0.1:5601", status_code=503)
    except Exception as e:
        if should_close:
            await client.aclose()
        logger.warning("Error proxying request to Kibana at %s: %s", target_path, e)
        return Response(content=f"Kibana Proxy Error: {e}", status_code=502)

    res_headers = {}
    for k, v in resp.headers.items():
        if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() not in ("content-length", "content-encoding"):
            res_headers[k] = v

    if "location" in res_headers and res_headers["location"].startswith(config.KIBANA_HOST):
        res_headers["location"] = res_headers["location"][len(config.KIBANA_HOST):] or "/"

    async def close_resources():
        await resp.aclose()
        if should_close:
            await client.aclose()

    if resp.status_code in (204, 304):
        await close_resources()
        return Response(status_code=resp.status_code, headers=res_headers)

    return StreamingResponse(
        resp.aiter_bytes(),
        status_code=resp.status_code,
        headers=res_headers,
        background=BackgroundTask(close_resources)
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def kibana_proxy_catchall(request: Request, path: str):
    """Fallback reverse proxy forwarding all non-FastAPI paths to Kibana."""
    return await forward_to_kibana(request, path)


if __name__ == "__main__":
    import uvicorn
    # Bind exclusively to localhost / 127.0.0.1
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
