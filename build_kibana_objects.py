"""
Builder script to generate pure Lens-based Kibana 8.13 saved objects for:
1. Data Views: security-alerts* and security-events*
2. Lens Metric Panels (lnsMetric):
   - metric-total-alerts (total alerts counter)
   - metric-critical-alerts (critical alerts counter)
   - metric-high-alerts (high alerts counter)
   - metric-unique-source-ips (distinct attacker source IPs counter)
   - metric-affected-hosts (distinct impacted hosts counter)
3. Lens Visualizations (lnsXY & lnsDatatable):
   - alerts-by-severity (stacked bar: timestamp x severity)
   - alerts-by-rule (horizontal bar: alert count by detection rule)
   - alerts-by-mitre (bar chart: alert count by MITRE ATT&CK technique)
   - alerts-by-user (bar chart: alert count by target user)
   - alerts-by-host (bar chart: alert count by affected host)
   - events-by-source (bar chart: event count by log source)
   - top-source-ips (data table: top src_ip by alert count)
   - suspicious-execution-hosts (data table: host & user breakdown filtered by rule)
   - recent-alerts-table (data table: timestamp, rule, sev, user, ip, host, mitre, count)
   - timeline-events-over-time (stacked bar: timestamp x event_type)
4. Saved Search: events-search (Discover search on security-events*)
5. Dashboards:
   - SOC Triage Board (Comprehensive Security Operations & Incident Response Board)
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
            "emptyAsNull": False,
            "format": {
                "id": "number",
                "params": {
                    "decimals": 0
                }
            }
        }
    }


def make_cardinality_col(source_field: str, label: str):
    return {
        "label": label,
        "dataType": "number",
        "operationType": "unique_count",
        "isBucketed": False,
        "scale": "ratio",
        "sourceField": source_field,
        "params": {
            "emptyAsNull": False,
            "format": {
                "id": "number",
                "params": {
                    "decimals": 0
                }
            }
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


def make_terms_col(source_field: str, label: str, size: int = 10, order_by_col: str | None = None, alphabetical: bool = False, desc: bool = False):
    if alphabetical:
        order_by = {"type": "alphabetical"}
        order_dir = "desc" if desc else "asc"
    elif order_by_col:
        order_by = {"type": "column", "columnId": order_by_col}
        order_dir = "desc" if desc else "asc"
    else:
        order_by = {"type": "alphabetical"}
        order_dir = "desc" if desc else "asc"
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
                "colorCode": "#8E0000"
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
                "colorCode": "#E7664C"
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

EVENT_TYPE_COLOR_MAPPING = {
    "assignments": [
        {"rule": {"type": "matchExactly", "values": ["authentication_failure"]}, "color": {"type": "colorCode", "colorCode": "#E7664C"}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["authentication_success"]}, "color": {"type": "colorCode", "colorCode": "#54B399"}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["process_creation"]}, "color": {"type": "colorCode", "colorCode": "#9170B8"}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["network_connection"]}, "color": {"type": "colorCode", "colorCode": "#DA8B45"}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["file_modification"]}, "color": {"type": "colorCode", "colorCode": "#D6BF57"}, "touched": True}
    ],
    "specialAssignments": [
        {"rule": {"type": "other"}, "color": {"type": "loop"}, "touched": False}
    ],
    "paletteId": "eui_amsterdam_color_blind",
    "colorMode": {"type": "categorical"}
}


def make_metric_object(obj_id: str, title: str, description: str, col_dict: dict, query_str: str = ""):
    return {
        "id": obj_id,
        "type": "lens",
        "coreMigrationVersion": "8.8.0",
        "typeMigrationVersion": "8.9.0",
        "attributes": {
            "title": title,
            "description": description,
            "visualizationType": "lnsMetric",
            "state": {
                "datasourceStates": {
                    "formBased": {
                        "layers": {
                            "layer_1": {
                                "columnOrder": ["col_metric"],
                                "columns": {
                                    "col_metric": col_dict
                                },
                                "incompleteColumns": {}
                            }
                        }
                    }
                },
                "filters": [],
                "query": {"language": "kuery", "query": query_str},
                "visualization": {
                    "layerId": "layer_1",
                    "layerType": "data",
                    "metricAccessor": "col_metric"
                }
            }
        },
        "references": [
            {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
            {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
        ]
    }


# Top row metric panels (lnsMetric)
objects.append(make_metric_object(
    "metric-total-alerts",
    "Total Alerts",
    "Total security alerts generated across all detection rules",
    make_count_col("Total Alerts")
))

objects.append(make_metric_object(
    "metric-critical-alerts",
    "Critical Alerts",
    "Total critical severity alerts requiring immediate escalation",
    make_count_col("Critical Alerts"),
    'severity: "critical"'
))

objects.append(make_metric_object(
    "metric-high-alerts",
    "High Alerts",
    "Total high severity alerts requiring active analyst investigation",
    make_count_col("High Alerts"),
    'severity: "high"'
))

objects.append(make_metric_object(
    "metric-unique-source-ips",
    "Unique Source IPs",
    "Distinct external or internal source IP addresses initiating threats",
    make_cardinality_col("src_ip", "Unique Source IPs")
))

objects.append(make_metric_object(
    "metric-affected-hosts",
    "Affected Hosts",
    "Distinct endpoints and servers impacted by security alerts",
    make_cardinality_col("host", "Affected Hosts")
))


# 3. Lens: Alerts by Severity Over Time
objects.append({
    "id": "alerts-by-severity",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts by Severity Over Time",
        "description": "Alert volume trends partitioned by severity over time",
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

# 6. Lens: Alerts by Detection Rule (Horizontal Bar, sorted by count)
objects.append({
    "id": "alerts-by-rule",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts by Detection Rule",
        "description": "Alert frequency broken down by correlation rule (Horizontal Bar)",
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
                "preferredSeriesType": "bar_horizontal",
                "isHorizontal": True,
                "legend": {"isVisible": False, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "seriesType": "bar_horizontal",
                        "xAccessor": "col_rule",
                        "accessors": ["col_count"],
                        "yConfig": [{"forAccessor": "col_count", "color": "#E7664C"}],
                        "color": "#E7664C"
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

# 7. Lens: Alerts by MITRE Technique (Bar chart on mitre_technique)
objects.append({
    "id": "alerts-by-mitre",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Alerts by MITRE Technique",
        "description": "Alert volume broken down by MITRE ATT&CK technique",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_mitre", "col_count"],
                            "columns": {
                                "col_mitre": make_terms_col("mitre_technique", "MITRE Technique", size=10, order_by_col="col_count"),
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
                        "xAccessor": "col_mitre",
                        "accessors": ["col_count"],
                        "yConfig": [{"forAccessor": "col_count", "color": "#9170B8"}],
                        "color": "#9170B8"
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

# 8. Lens: Alerts by User
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
                        "accessors": ["col_count"],
                        "yConfig": [{"forAccessor": "col_count", "color": "#DA8B45"}],
                        "color": "#DA8B45"
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

# 9. Lens: Alerts by Host (Multi-value keyword field, one row per host)
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
                        "accessors": ["col_count"],
                        "yConfig": [{"forAccessor": "col_count", "color": "#AA6556"}],
                        "color": "#AA6556"
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

# 10. Lens Data Table: Recent Security Alerts (Detailed tabular record, newest first, 10+ rows)
objects.append({
    "id": "recent-alerts-table",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Recent Security Alerts",
        "description": "Detailed tabular record of recent alerts (first_seen, rule, sev, user, ip, host, mitre, count)",
        "visualizationType": "lnsDatatable",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_time", "col_rule", "col_sev", "col_user", "col_ip", "col_host", "col_mitre", "col_count"],
                            "columns": {
                                "col_time": make_terms_col("first_seen", "Timestamp", size=25, alphabetical=True, desc=True),
                                "col_rule": make_terms_col("rule_name", "Rule Name", size=10, alphabetical=True),
                                "col_sev": make_terms_col("severity", "Severity", size=5, alphabetical=True),
                                "col_user": make_terms_col("user", "User", size=5, alphabetical=True),
                                "col_ip": make_terms_col("src_ip", "Source IP", size=5, alphabetical=True),
                                "col_host": make_terms_col("host", "Host", size=5, alphabetical=True),
                                "col_mitre": make_terms_col("mitre_technique", "MITRE Technique", size=5, alphabetical=True),
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
                    {"columnId": "col_time", "isTransposed": False},
                    {"columnId": "col_rule", "isTransposed": False},
                    {"columnId": "col_sev", "isTransposed": False},
                    {"columnId": "col_user", "isTransposed": False},
                    {"columnId": "col_ip", "isTransposed": False},
                    {"columnId": "col_host", "isTransposed": False},
                    {"columnId": "col_mitre", "isTransposed": False},
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

# 11. Lens: Timeline Events Over Time (from security-events*)
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
                        "splitAccessor": "col_type",
                        "colorMapping": EVENT_TYPE_COLOR_MAPPING
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

# 12. Lens: Events by Log Source (from security-events*)
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
                        "accessors": ["col_count"],
                        "yConfig": [{"forAccessor": "col_count", "color": "#54B399"}],
                        "color": "#54B399"
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

# 13. Saved Search: events-search (Discover search on security-events*)
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

# 14. Dashboard: SOC Triage Board (Comprehensive Security Overview & Incident Response Board)
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
        "timeFrom": "now-7d",
        "timeTo": "now+1d",
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps([
            # Top row: 5 Metric counters (y: 0, h: 6, w: 10, 9, 9, 10, 10 = 48)
            {"version": "8.13.0", "panelIndex": "panel-1", "gridData": {"x": 0, "y": 0, "w": 10, "h": 6, "i": "panel-1"}, "panelRefName": "panel_panel-1"},
            {"version": "8.13.0", "panelIndex": "panel-2", "gridData": {"x": 10, "y": 0, "w": 9, "h": 6, "i": "panel-2"}, "panelRefName": "panel_panel-2"},
            {"version": "8.13.0", "panelIndex": "panel-3", "gridData": {"x": 19, "y": 0, "w": 9, "h": 6, "i": "panel-3"}, "panelRefName": "panel_panel-3"},
            {"version": "8.13.0", "panelIndex": "panel-4", "gridData": {"x": 28, "y": 0, "w": 10, "h": 6, "i": "panel-4"}, "panelRefName": "panel_panel-4"},
            {"version": "8.13.0", "panelIndex": "panel-5", "gridData": {"x": 38, "y": 0, "w": 10, "h": 6, "i": "panel-5"}, "panelRefName": "panel_panel-5"},

            # Middle Row 1: Alerts by Severity Over Time & Alerts by Detection Rule (y: 6, h: 12)
            {"version": "8.13.0", "panelIndex": "panel-6", "gridData": {"x": 0, "y": 6, "w": 24, "h": 12, "i": "panel-6"}, "panelRefName": "panel_panel-6"},
            {"version": "8.13.0", "panelIndex": "panel-7", "gridData": {"x": 24, "y": 6, "w": 24, "h": 12, "i": "panel-7"}, "panelRefName": "panel_panel-7"},

            # Middle Row 2: Alerts by MITRE Technique & Events by Log Source (y: 18, h: 12)
            {"version": "8.13.0", "panelIndex": "panel-8", "gridData": {"x": 0, "y": 18, "w": 24, "h": 12, "i": "panel-8"}, "panelRefName": "panel_panel-8"},
            {"version": "8.13.0", "panelIndex": "panel-9", "gridData": {"x": 24, "y": 18, "w": 24, "h": 12, "i": "panel-9"}, "panelRefName": "panel_panel-9"},

            # Middle Row 3: Top Users & Top Hosts (y: 30, h: 12)
            {"version": "8.13.0", "panelIndex": "panel-10", "gridData": {"x": 0, "y": 30, "w": 24, "h": 12, "i": "panel-10"}, "panelRefName": "panel_panel-10"},
            {"version": "8.13.0", "panelIndex": "panel-11", "gridData": {"x": 24, "y": 30, "w": 24, "h": 12, "i": "panel-11"}, "panelRefName": "panel_panel-11"},

            # Bottom Row 1: Top Source IPs & Hosts with Post-Logon Suspicious Execution (y: 42, h: 12)
            {"version": "8.13.0", "panelIndex": "panel-12", "gridData": {"x": 0, "y": 42, "w": 24, "h": 12, "i": "panel-12"}, "panelRefName": "panel_panel-12"},
            {"version": "8.13.0", "panelIndex": "panel-13", "gridData": {"x": 24, "y": 42, "w": 24, "h": 12, "i": "panel-13"}, "panelRefName": "panel_panel-13"},

            # Bottom Row 2: Recent Security Alerts Detailed Table (y: 54, h: 14)
            {"version": "8.13.0", "panelIndex": "panel-14", "gridData": {"x": 0, "y": 54, "w": 48, "h": 14, "i": "panel-14"}, "panelRefName": "panel_panel-14"}
        ]),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"id": "metric-total-alerts", "name": "panel_panel-1", "type": "lens"},
        {"id": "metric-critical-alerts", "name": "panel_panel-2", "type": "lens"},
        {"id": "metric-high-alerts", "name": "panel_panel-3", "type": "lens"},
        {"id": "metric-unique-source-ips", "name": "panel_panel-4", "type": "lens"},
        {"id": "metric-affected-hosts", "name": "panel_panel-5", "type": "lens"},
        {"id": "alerts-by-severity", "name": "panel_panel-6", "type": "lens"},
        {"id": "alerts-by-rule", "name": "panel_panel-7", "type": "lens"},
        {"id": "alerts-by-mitre", "name": "panel_panel-8", "type": "lens"},
        {"id": "events-by-source", "name": "panel_panel-9", "type": "lens"},
        {"id": "alerts-by-user", "name": "panel_panel-10", "type": "lens"},
        {"id": "alerts-by-host", "name": "panel_panel-11", "type": "lens"},
        {"id": "top-source-ips", "name": "panel_panel-12", "type": "lens"},
        {"id": "suspicious-execution-hosts", "name": "panel_panel-13", "type": "lens"},
        {"id": "recent-alerts-table", "name": "panel_panel-14", "type": "lens"}
    ]
})

# 15. Dashboard: Alerts Dashboard
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
        "timeFrom": "now-7d",
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

# 16. Dashboard: Timeline Analysis Dashboard
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
        "timeFrom": "now-7d",
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
