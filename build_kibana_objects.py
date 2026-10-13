"""
Builder script to generate pure Lens-based Kibana 8.13 saved objects for:
1. Data Views: security-alerts* and security-events*
2. Lens Visualizations (lnsXY & lnsDatatable):
   - alerts-by-severity (stacked bar: timestamp x severity)
   - top-source-ips (data table: top src_ip by alert count)
   - suspicious-execution-hosts (data table: host & user breakdown filtered by rule)
   - alerts-by-rule (bar chart: alert count by detection rule)
   - alerts-by-user (bar chart: alert count by target user)
   - alerts-by-host (bar chart: alert count by affected host)
   - recent-alerts-table (data table: rule, sev, user, ip, host, count)
   - timeline-events-over-time (stacked bar: timestamp x event_type)
   - events-by-source (bar chart: event count by log source)
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


def make_count_col(label: str = "Count"):
    return {
        "label": label,
        "dataType": "number",
        "operationType": "count",
        "isBucketed": False,
        "scale": "ratio",
        "sourceField": "___records___",
        "params": {
            "emptyAsNull": False
        }
    }


def make_date_histogram_col(source_field: str, label: str = "Timestamp"):
    return {
        "label": label,
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": source_field,
        "isBucketed": True,
        "scale": "interval",
        "params": {
            "interval": "auto",
            "includeEmptyRows": True,
            "dropPartials": False
        }
    }


def make_terms_col(source_field: str, label: str, size: int = 10, order_by_col: str | None = None, alphabetical: bool = False):
    if alphabetical:
        order_by = {"type": "alphabetical"}
        order_dir = "asc"
    elif order_by_col:
        order_by = {"type": "column", "columnId": order_by_col}
        order_dir = "desc"
    else:
        order_by = {"type": "alphabetical"}
        order_dir = "asc"
    return {
        "label": label,
        "dataType": "string",
        "operationType": "terms",
        "scale": "ordinal",
        "sourceField": source_field,
        "isBucketed": True,
        "params": {
            "size": size,
            "orderBy": order_by,
            "orderDirection": order_dir,
            "otherBucket": False,
            "missingBucket": False,
            "parentFormat": {"id": "terms"}
        }
    }


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

SEVERITY_COLOR_MAPPING = {
    "assignments": [
        {
            "rule": {
                "type": "matchExactly",
                "values": ["critical", "Critical"]
            },
            "color": {
                "type": "colorCode",
                "colorCode": "#BD271E"
            },
            "touched": True
        },
        {
            "rule": {
                "type": "matchExactly",
                "values": ["high", "High"]
            },
            "color": {
                "type": "colorCode",
                "colorCode": "#F5A700"
            },
            "touched": True
        },
        {
            "rule": {
                "type": "matchExactly",
                "values": ["medium", "Medium"]
            },
            "color": {
                "type": "colorCode",
                "colorCode": "#FEC514"
            },
            "touched": True
        },
        {
            "rule": {
                "type": "matchExactly",
                "values": ["low", "Low"]
            },
            "color": {
                "type": "colorCode",
                "colorCode": "#54B399"
            },
            "touched": True
        }
    ],
    "specialAssignments": [
        {
            "rule": {
                "type": "other"
            },
            "color": {
                "type": "loop"
            },
            "touched": False
        }
    ],
    "paletteId": "eui_amsterdam_color_blind",
    "colorMode": {
        "type": "categorical"
    }
}


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
                            "columnOrder": ["col_date", "col_severity", "col_count"],
                            "columns": {
                                "col_date": make_date_histogram_col("first_seen", "Timestamp"),
                                "col_severity": make_terms_col("severity", "Severity", size=5, alphabetical=True),
                                "col_count": make_count_col("Alert Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": True,
                "preferredSeriesType": "bar_stacked",
                "legend": {"isVisible": True, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar_stacked",
                        "xAccessor": "col_date",
                        "accessors": ["col_count"],
                        "splitAccessor": "col_severity",
                        "colorMapping": SEVERITY_COLOR_MAPPING
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

# 4. Lens Data Table: Top Source IPs
objects.append({
    "id": "top-source-ips",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Top Source IPs",
        "description": "Top source IP addresses by alert frequency (Data Table)",
        "visualizationType": "lnsDatatable",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_ip", "col_count"],
                            "columns": {
                                "col_ip": make_terms_col("src_ip", "Source IP", size=10, order_by_col="col_count"),
                                "col_count": make_count_col("Alert Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "layerId": "layer_1",
                "layerType": "data",
                "columns": [
                    {"columnId": "col_ip", "isTransposed": False},
                    {"columnId": "col_count", "isTransposed": False}
                ]
            }
        }
    },
    "references": [
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 5. Lens Data Table: Hosts with Post-Logon Suspicious Execution
objects.append({
    "id": "suspicious-execution-hosts",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Hosts with Post-Logon Suspicious Execution",
        "description": "Endpoints impacted by suspicious post-logon execution (Data Table)",
        "visualizationType": "lnsDatatable",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_host", "col_user", "col_count"],
                            "columns": {
                                "col_host": make_terms_col("host", "Host", size=10, order_by_col="col_count"),
                                "col_user": make_terms_col("user", "User", size=5, order_by_col="col_count"),
                                "col_count": make_count_col("Alert Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": 'rule_name: "Post-Logon Suspicious Execution"'},
            "visualization": {
                "layerId": "layer_1",
                "layerType": "data",
                "columns": [
                    {"columnId": "col_host", "isTransposed": False},
                    {"columnId": "col_user", "isTransposed": False},
                    {"columnId": "col_count", "isTransposed": False}
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
                                "col_rule": make_terms_col("rule_name", "Rule Name", size=10, order_by_col="col_count"),
                                "col_count": make_count_col("Alert Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": False,
                "preferredSeriesType": "bar",
                "legend": {"isVisible": False, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
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

# 7. Lens: Alerts by User
objects.append({
    "id": "alerts-by-user",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts by User",
        "description": "Alert volume broken down by target user",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_user", "col_count"],
                            "columns": {
                                "col_user": make_terms_col("user", "User", size=10, order_by_col="col_count"),
                                "col_count": make_count_col("Alert Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": False,
                "preferredSeriesType": "bar",
                "legend": {"isVisible": False, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar",
                        "xAccessor": "col_user",
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

# 8. Lens: Alerts by Host
objects.append({
    "id": "alerts-by-host",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts by Host",
        "description": "Alert volume broken down by affected endpoint or host",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_host", "col_count"],
                            "columns": {
                                "col_host": make_terms_col("host", "Host", size=10, order_by_col="col_count"),
                                "col_count": make_count_col("Alert Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": False,
                "preferredSeriesType": "bar",
                "legend": {"isVisible": False, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar",
                        "xAccessor": "col_host",
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

# 9. Lens Data Table: Recent Security Alerts
objects.append({
    "id": "recent-alerts-table",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Recent Security Alerts",
        "description": "Detailed tabular record of recent alerts (Data Table)",
        "visualizationType": "lnsDatatable",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_rule", "col_sev", "col_user", "col_ip", "col_host", "col_count"],
                            "columns": {
                                "col_rule": make_terms_col("rule_name", "Rule Name", size=20, order_by_col="col_count"),
                                "col_sev": make_terms_col("severity", "Severity", size=5, alphabetical=True),
                                "col_user": make_terms_col("user", "User", size=5, alphabetical=True),
                                "col_ip": make_terms_col("src_ip", "Source IP", size=5, alphabetical=True),
                                "col_host": make_terms_col("host", "Host", size=5, alphabetical=True),
                                "col_count": make_count_col("Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "layerId": "layer_1",
                "layerType": "data",
                "columns": [
                    {"columnId": "col_rule", "isTransposed": False},
                    {"columnId": "col_sev", "isTransposed": False},
                    {"columnId": "col_user", "isTransposed": False},
                    {"columnId": "col_ip", "isTransposed": False},
                    {"columnId": "col_host", "isTransposed": False},
                    {"columnId": "col_count", "isTransposed": False}
                ]
            }
        }
    },
    "references": [
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
        {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
    ]
})

# 10. Lens: Timeline Events Over Time (from security-events*)
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
                            "columnOrder": ["col_date", "col_type", "col_count"],
                            "columns": {
                                "col_date": make_date_histogram_col("timestamp", "Timestamp"),
                                "col_type": make_terms_col("event_type", "Event Type", size=5, order_by_col="col_count"),
                                "col_count": make_count_col("Event Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": True,
                "preferredSeriesType": "bar_stacked",
                "legend": {"isVisible": True, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
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

# 11. Lens: Events by Log Source
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
                                "col_source": make_terms_col("source", "Source", size=5, order_by_col="col_count"),
                                "col_count": make_count_col("Event Count")
                            },
                            "incompleteColumns": {}
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "bars",
                "isStacked": False,
                "preferredSeriesType": "bar",
                "legend": {"isVisible": False, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
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

# 12. Saved Search: events-search (Discover search on security-events*)
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

# 13. Dashboard: SOC Triage Board (Security Overview)
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

# 14. Dashboard: Alerts Dashboard
objects.append({
    "id": "alerts-dashboard",
    "type": "dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts Dashboard",
        "description": "Generated alerts by rule, severity, user, host, top IPs, and recent alerts table",
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
                "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "panel-3"},
                "panelRefName": "panel_panel-3"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-4",
                "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "panel-4"},
                "panelRefName": "panel_panel-4"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-5",
                "gridData": {"x": 0, "y": 30, "w": 48, "h": 15, "i": "panel-5"},
                "panelRefName": "panel_panel-5"
            },
            {
                "version": "8.13.0",
                "panelIndex": "panel-6",
                "gridData": {"x": 0, "y": 45, "w": 48, "h": 15, "i": "panel-6"},
                "panelRefName": "panel_panel-6"
            }
        ]),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"id": "alerts-by-rule", "name": "panel_panel-1", "type": "lens"},
        {"id": "alerts-by-severity", "name": "panel_panel-2", "type": "lens"},
        {"id": "alerts-by-user", "name": "panel_panel-3", "type": "lens"},
        {"id": "alerts-by-host", "name": "panel_panel-4", "type": "lens"},
        {"id": "top-source-ips", "name": "panel_panel-5", "type": "lens"},
        {"id": "recent-alerts-table", "name": "panel_panel-6", "type": "lens"}
    ]
})

# 15. Dashboard: Timeline Analysis Dashboard
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
