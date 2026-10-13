"""
Builder script to generate pure Lens-based Kibana 8.13 saved objects for:
1. Data Views: security-alerts* and security-events*
2. Lens Visualizations (lnsXY):
   - alerts-by-severity (stacked bar: timestamp x severity)
   - top-source-ips (horizontal bar: top src_ip)
   - suspicious-execution-hosts (host & user breakdown filtered by rule)
   - alerts-by-rule (breakdown by detection rule name)
   - timeline-events-over-time (events histogram x event_type)
   - events-by-source (events by log source)
3. Saved Search: events-search (Discover search on security-events*)
4. Dashboards:
   - SOC Triage Board (Security Overview)
   - Alerts Dashboard
   - Timeline Analysis Dashboard
"""

import json
from pathlib import Path

NDJSON_PATH = Path(__file__).resolve().parent / "soc_triage_board.ndjson"

ALERTS_DV_ID = "security-alerts-dataview"
EVENTS_DV_ID = "security-events-dataview"

objects = []

# 1. Data View: security-alerts*
objects.append({
    "id": ALERTS_DV_ID,
    "type": "index-pattern",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.0.0",
    "attributes": {
        "title": "security-alerts*",
        "name": "Security Alerts",
        "timeFieldName": "first_seen",
        "fields": "[]",
        "fieldAttrs": "{}",
        "fieldFormatMap": "{}",
        "runtimeFieldMap": "{}",
        "sourceFilters": "[]",
        "allowHidden": False
    },
    "references": []
})

# 2. Data View: security-events*
objects.append({
    "id": EVENTS_DV_ID,
    "type": "index-pattern",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.0.0",
    "attributes": {
        "title": "security-events*",
        "name": "Security Events",
        "timeFieldName": "timestamp",
        "fields": "[]",
        "fieldAttrs": "{}",
        "fieldFormatMap": "{}",
        "runtimeFieldMap": "{}",
        "sourceFilters": "[]",
        "allowHidden": False
    },
    "references": []
})

# 3. Lens: Alerts by Severity Over Time
objects.append({
    "id": "alerts-by-severity",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts by Severity Over Time",
        "description": "Alerts by severity over time",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_date", "col_count", "col_severity"],
                            "columns": {
                                "col_date": {
                                    "label": "Timestamp",
                                    "operationType": "date_histogram",
                                    "params": {"interval": "auto"},
                                    "sourceField": "first_seen"
                                },
                                "col_count": {
                                    "label": "Alert Count",
                                    "operationType": "count"
                                },
                                "col_severity": {
                                    "label": "Severity",
                                    "operationType": "terms",
                                    "params": {
                                        "size": 5,
                                        "orderBy": {"type": "alphabetical", "direction": "asc"}
                                    },
                                    "sourceField": "severity"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": True,
                "legend": {"isVisible": True, "position": "right"},
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar_stacked",
                        "xAccessor": "col_date",
                        "accessors": ["col_count"],
                        "splitAccessor": "col_severity"
                    }
                ]
            }
        }
    },
    "references": [
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 4. Lens: Top Source IPs (Pure Lens Horizontal Bars)
objects.append({
    "id": "top-source-ips",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Top Source IPs",
        "description": "Top source IP addresses by alert frequency",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_ip", "col_count"],
                            "columns": {
                                "col_ip": {
                                    "label": "Source IP",
                                    "operationType": "terms",
                                    "params": {
                                        "size": 10,
                                        "orderBy": {"type": "column", "columnId": "col_count", "direction": "desc"}
                                    },
                                    "sourceField": "src_ip"
                                },
                                "col_count": {
                                    "label": "Alert Count",
                                    "operationType": "count"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": False,
                "legend": {"isVisible": False, "position": "right"},
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar",
                        "xAccessor": "col_ip",
                        "accessors": ["col_count"]
                    }
                ]
            }
        }
    },
    "references": [
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 5. Lens: Hosts with Post-Logon Suspicious Execution
objects.append({
    "id": "suspicious-execution-hosts",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Hosts with Post-Logon Suspicious Execution",
        "description": "Endpoints impacted by suspicious post-logon execution",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_host", "col_count", "col_user"],
                            "columns": {
                                "col_host": {
                                    "label": "Host",
                                    "operationType": "terms",
                                    "params": {
                                        "size": 10,
                                        "orderBy": {"type": "column", "columnId": "col_count", "direction": "desc"}
                                    },
                                    "sourceField": "host"
                                },
                                "col_count": {
                                    "label": "Alert Count",
                                    "operationType": "count"
                                },
                                "col_user": {
                                    "label": "User",
                                    "operationType": "terms",
                                    "params": {
                                        "size": 5,
                                        "orderBy": {"type": "column", "columnId": "col_count", "direction": "desc"}
                                    },
                                    "sourceField": "user"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": "rule_name: \"Post-Logon Suspicious Execution\""},
            "visualization": {
                "shape": "bars",
                "isStacked": True,
                "legend": {"isVisible": True, "position": "right"},
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar_stacked",
                        "xAccessor": "col_host",
                        "accessors": ["col_count"],
                        "splitAccessor": "col_user"
                    }
                ]
            }
        }
    },
    "references": [
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 6. Lens: Alerts by Detection Rule
objects.append({
    "id": "alerts-by-rule",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts by Detection Rule",
        "description": "Alert frequency broken down by correlation rule",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_rule", "col_count"],
                            "columns": {
                                "col_rule": {
                                    "label": "Rule Name",
                                    "operationType": "terms",
                                    "params": {
                                        "size": 10,
                                        "orderBy": {"type": "column", "columnId": "col_count", "direction": "desc"}
                                    },
                                    "sourceField": "rule_name"
                                },
                                "col_count": {
                                    "label": "Count",
                                    "operationType": "count"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": False,
                "legend": {"isVisible": False, "position": "right"},
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar",
                        "xAccessor": "col_rule",
                        "accessors": ["col_count"]
                    }
                ]
            }
        }
    },
    "references": [
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 7. Lens: Timeline Events Over Time (from security-events*)
objects.append({
    "id": "timeline-events-over-time",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Security Events Over Time",
        "description": "Normalized telemetry volume over time by event type",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_date", "col_count", "col_type"],
                            "columns": {
                                "col_date": {
                                    "label": "Timestamp",
                                    "operationType": "date_histogram",
                                    "params": {"interval": "auto"},
                                    "sourceField": "timestamp"
                                },
                                "col_count": {
                                    "label": "Event Count",
                                    "operationType": "count"
                                },
                                "col_type": {
                                    "label": "Event Type",
                                    "operationType": "terms",
                                    "params": {
                                        "size": 5,
                                        "orderBy": {"type": "column", "columnId": "col_count", "direction": "desc"}
                                    },
                                    "sourceField": "event_type"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": True,
                "legend": {"isVisible": True, "position": "right"},
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar_stacked",
                        "xAccessor": "col_date",
                        "accessors": ["col_count"],
                        "splitAccessor": "col_type"
                    }
                ]
            }
        }
    },
    "references": [
        {"id": EVENTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": EVENTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 8. Lens: Events by Log Source
objects.append({
    "id": "events-by-source",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Events by Log Source",
        "description": "Normalized event count grouped by log source",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_source", "col_count"],
                            "columns": {
                                "col_source": {
                                    "label": "Source",
                                    "operationType": "terms",
                                    "params": {
                                        "size": 5,
                                        "orderBy": {"type": "column", "columnId": "col_count", "direction": "desc"}
                                    },
                                    "sourceField": "source"
                                },
                                "col_count": {
                                    "label": "Count",
                                    "operationType": "count"
                                }
                            }
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": False,
                "legend": {"isVisible": False, "position": "right"},
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar",
                        "xAccessor": "col_source",
                        "accessors": ["col_count"]
                    }
                ]
            }
        }
    },
    "references": [
        {"id": EVENTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": EVENTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 9. Saved Search: events-search (Discover search on security-events*)
objects.append({
    "id": "events-search",
    "type": "search",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.0.0",
    "attributes": {
        "title": "Security Events Raw Search",
        "description": "Discover search across normalized security-events telemetry",
        "columns": ["timestamp", "source", "event_type", "user", "source_ip", "host", "process_name"],
        "sort": [["timestamp", "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"query": "", "language": "kuery"},
                "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"
            })
        }
    },
    "references": [
        {"id": EVENTS_DV_ID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}
    ]
})

# 10. Dashboard: SOC Triage Board (Security Overview)
objects.append({
    "id": "soc-triage-board-dashboard",
    "type": "dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "SOC Triage Board",
        "description": "BCSSL Lab 07 - SIEM Alert Triage and Incident Response Board",
        "hits": 0,
        "timeRestore": True,
        "timeFrom": "now-30d",
        "timeTo": "now+1d",
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps([
            {
                "version": "8.13.0",
                "panelIndex": "panel-1",
                "gridData": {"x": 0, "y": 0, "w": 48, "h": 15, "i": "panel-1"},
                "panelRefName": "panel_panel-1"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-2",
                "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "panel-2"},
                "panelRefName": "panel_panel-2"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-3",
                "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "panel-3"},
                "panelRefName": "panel_panel-3"
            }
        ]),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"id": "alerts-by-severity", "name": "panel_panel-1", "type": "lens"},
        {"id": "top-source-ips", "name": "panel_panel-2", "type": "lens"},
        {"id": "suspicious-execution-hosts", "name": "panel_panel-3", "type": "lens"}
    ]
})

# 11. Dashboard: Alerts Dashboard
objects.append({
    "id": "alerts-dashboard",
    "type": "dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts Dashboard",
        "description": "Generated alerts by rule, severity, and impacted source",
        "hits": 0,
        "timeRestore": True,
        "timeFrom": "now-30d",
        "timeTo": "now+1d",
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps([
            {
                "version": "8.13.0",
                "panelIndex": "panel-1",
                "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "panel-1"},
                "panelRefName": "panel_panel-1"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-2",
                "gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "panel-2"},
                "panelRefName": "panel_panel-2"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-3",
                "gridData": {"x": 0, "y": 15, "w": 48, "h": 15, "i": "panel-3"},
                "panelRefName": "panel_panel-3"
            }
        ]),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"id": "alerts-by-rule", "name": "panel_panel-1", "type": "lens"},
        {"id": "alerts-by-severity", "name": "panel_panel-2", "type": "lens"},
        {"id": "top-source-ips", "name": "panel_panel-3", "type": "lens"}
    ]
})

# 12. Dashboard: Timeline Analysis Dashboard
objects.append({
    "id": "timeline-analysis-dashboard",
    "type": "dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Timeline Analysis",
        "description": "Chronological timeline analysis of normalized security events",
        "hits": 0,
        "timeRestore": True,
        "timeFrom": "now-30d",
        "timeTo": "now+1d",
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps([
            {
                "version": "8.13.0",
                "panelIndex": "panel-1",
                "gridData": {"x": 0, "y": 0, "w": 48, "h": 15, "i": "panel-1"},
                "panelRefName": "panel_panel-1"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-2",
                "gridData": {"x": 0, "y": 15, "w": 48, "h": 15, "i": "panel-2"},
                "panelRefName": "panel_panel-2"
            }
        ]),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"id": "timeline-events-over-time", "name": "panel_panel-1", "type": "lens"},
        {"id": "events-by-source", "name": "panel_panel-2", "type": "lens"}
    ]
})

with open(NDJSON_PATH, "w", encoding="utf-8") as f:
    for obj in objects:
        f.write(json.dumps(obj) + "\n")

print(f"Generated {len(objects)} Kibana saved objects into {NDJSON_PATH.name}")
