"""
Builder script to generate pure Lens-based Kibana 8.13 saved objects for:
1. Data Views: security-alerts* and security-events*
2. Lens Metric Panels (lnsMetric):
   - metric-total-alerts (Total alerts: #F1EFE8 card, text #2C2C2A)
   - metric-critical-alerts (Critical alerts: #8E0000 card, white text)
   - metric-high-alerts (High alerts: #E7664C card, text #4A1B0C)
   - metric-medium-alerts (Medium alerts: #FEC514 card, text #412402)
   - metric-unique-source-ips (Unique Source IPs)
   - metric-affected-hosts (Affected Hosts)
3. Lens Visualizations:
   - alerts-by-severity (stacked bar: timestamp x severity)
   - event-categories-pie (pie chart: event_type distribution from security-events*)
   - top-hosts-by-events (horizontal bar: top 10 hosts by event count from security-events*)
   - recent-alerts-table (data table: first_seen, rule_name, severity, user, source_ip, host, mitre_technique)
   - events-by-source-donut (donut chart: source distribution from security-events*)
   - top-source-ips (data table: top src_ip by alert count)
   - suspicious-execution-hosts (data table: host & user breakdown filtered by rule)
   - alerts-by-rule (horizontal bar: alert count by detection rule)
   - alerts-by-mitre (bar chart: alert count by MITRE ATT&CK technique)
   - alerts-by-user (bar chart: alert count by target user)
   - alerts-by-host (bar chart: alert count by affected host)
   - timeline-events-over-time (stacked bar: timestamp x event_type)
   - events-by-source (bar chart: event count by log source)
4. Saved Search: events-search (Discover search on security-events*)
5. Dashboards:
   - SOC Triage Board (Analyst board layout matching reference)
   - Alerts Dashboard
   - Timeline Analysis Dashboard
"""

import json
from pathlib import Path

NDJSON_PATH = Path(__file__).resolve().parent / "soc_triage_board.ndjson"

ALERTS_DV_ID = "security-alerts-dataview"
EVENTS_DV_ID = "security-events-dataview"

# ===========================================================================
# CONSTANTS: COLOR PALETTE
# ===========================================================================
# Count cards
COUNT_CARD_TOTAL_BG = "#F1EFE8"
COUNT_CARD_TOTAL_TEXT = "#2C2C2A"
COUNT_CARD_CRITICAL_BG = "#8E0000"
COUNT_CARD_CRITICAL_TEXT = "#FFFFFF"
COUNT_CARD_HIGH_BG = "#E7664C"
COUNT_CARD_HIGH_TEXT = "#4A1B0C"
COUNT_CARD_MEDIUM_BG = "#FEC514"
COUNT_CARD_MEDIUM_TEXT = "#412402"

# Severity series everywhere
SEVERITY_CRITICAL = "#8E0000"
SEVERITY_HIGH = "#E7664C"
SEVERITY_MEDIUM = "#FEC514"
SEVERITY_LOW = "#54B399"

# Chart palette (reds with lavender accents)
CHART_PALETTE = [
    "#E8483B",
    "#C21807",
    "#F28B82",
    "#F6B5AE",
    "#FBDAD6",
    "#6C73D6",
    "#C9CCF2"
]

# Panel label tags
TAG_COLOR = "#2B2F7E"  # navy, white text


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


def make_date_histogram_col(source_field: str, label: str = "Timestamp", desc: bool = False):
    params = {
        "interval": "auto",
        "includeEmptyRows": False if desc else True,
        "dropPartials": False
    }
    if desc:
        params["orderDirection"] = "desc"
    return {
        "label": label,
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": source_field,
        "isBucketed": True,
        "scale": "interval",
        "params": params
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
                "colorCode": SEVERITY_CRITICAL
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
                "colorCode": SEVERITY_HIGH
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
                "colorCode": SEVERITY_MEDIUM
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
                "colorCode": SEVERITY_LOW
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
    "paletteId": "custom",
    "colorMode": {
        "type": "categorical"
    }
}

EVENT_TYPE_COLOR_MAPPING = {
    "assignments": [
        {"rule": {"type": "matchExactly", "values": ["logon_failure"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[0]}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["logon_success"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[1]}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["process_create"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[2]}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["network_connection"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[5]}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["file_access"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[3]}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["privilege_escalation"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[6]}, "touched": True}
    ],
    "specialAssignments": [
        {"rule": {"type": "other"}, "color": {"type": "loop"}, "touched": False}
    ],
    "paletteId": "custom",
    "colorMode": {"type": "categorical"}
}

LOG_SOURCE_COLOR_MAPPING = {
    "assignments": [
        {"rule": {"type": "matchExactly", "values": ["Windows", "windows_sysmon"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[0]}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["Linux", "linux_auditd"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[1]}, "touched": True},
        {"rule": {"type": "matchExactly", "values": ["Network", "network_firewall"]}, "color": {"type": "colorCode", "colorCode": CHART_PALETTE[5]}, "touched": True}
    ],
    "specialAssignments": [
        {"rule": {"type": "other"}, "color": {"type": "loop"}, "touched": False}
    ],
    "paletteId": "custom",
    "colorMode": {"type": "categorical"}
}


def make_metric_object(obj_id: str, title: str, description: str, col_dict: dict, query_str: str = "", color_code: str = "#2C2C2A"):
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
                    "metricAccessor": "col_metric",
                    "color": color_code
                }
            }
        },
        "references": [
            {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-layer-layer_1", "type": "index-pattern"},
            {"id": ALERTS_DV_ID, "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
        ]
    }


# ===========================================================================
# 3. METRIC OBJECTS (Count cards)
# ===========================================================================
# Card: Total #F1EFE8 (text #2C2C2A)
objects.append(make_metric_object(
    "metric-total-alerts",
    "Total alerts",
    "Total security alerts generated across all detection rules",
    make_count_col("Total alerts"),
    query_str="",
    color_code=COUNT_CARD_TOTAL_TEXT
))

# Card: Critical #8E0000 (white text)
objects.append(make_metric_object(
    "metric-critical-alerts",
    "Critical alerts",
    "Total critical severity alerts requiring immediate escalation",
    make_count_col("Critical alerts"),
    query_str='severity: "critical"',
    color_code=SEVERITY_CRITICAL
))

# Card: High #E7664C (text #4A1B0C)
objects.append(make_metric_object(
    "metric-high-alerts",
    "High alerts",
    "Total high severity alerts requiring active analyst investigation",
    make_count_col("High alerts"),
    query_str='severity: "high"',
    color_code=SEVERITY_HIGH
))

# Card: Medium #FEC514 (text #412402)
objects.append(make_metric_object(
    "metric-medium-alerts",
    "Medium alerts",
    "Total medium severity alerts requiring review",
    make_count_col("Medium alerts"),
    query_str='severity: "medium"',
    color_code=SEVERITY_MEDIUM
))

# Additional metrics for Alerts Dashboard
objects.append(make_metric_object(
    "metric-unique-source-ips",
    "Unique Source IPs",
    "Distinct external or internal source IP addresses initiating threats",
    make_cardinality_col("src_ip", "Unique Source IPs"),
    color_code=CHART_PALETTE[5]
))

objects.append(make_metric_object(
    "metric-affected-hosts",
    "Affected Hosts",
    "Distinct endpoints and servers impacted by security alerts",
    make_cardinality_col("host", "Affected Hosts"),
    color_code=CHART_PALETTE[0]
))


# ===========================================================================
# 4. ROW 2 PANELS
# ===========================================================================
# Panel 2A: Alerts by Severity Over Time (Stacked Bar)
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

# Panel 2B: Event categories (Pie on event_type from security-events*)
objects.append({
    "id": "event-categories-pie",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Event categories",
        "description": "Distribution of telemetry by event category",
        "visualizationType": "lnsPie",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_category", "col_count"],
                            "columns": {
                                "col_category": make_terms_col("event_type", "Event Category", size=7, order_by_col="col_count"),
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
                "shape": "pie",
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "primaryGroups": ["col_category"],
                        "metrics": ["col_count"],
                        "numberDisplay": "percent",
                        "categoryDisplay": "default",
                        "legendDisplay": "default",
                        "nestedLegend": False,
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

# Panel 2C: Top hosts by events (Horizontal Bar, top 10 hosts from security-events*)
objects.append({
    "id": "top-hosts-by-events",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Top hosts by events",
        "description": "Top 10 endpoints and hosts generating normalized security events",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer_1": {
                            "columnOrder": ["col_host", "col_count"],
                            "columns": {
                                "col_host": make_terms_col("host", "Host", size=10, order_by_col="col_count"),
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
                        "xAccessor": "col_host",
                        "accessors": ["col_count"],
                        "yConfig": [{"forAccessor": "col_count", "color": CHART_PALETTE[0]}],
                        "color": CHART_PALETTE[0]
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


# ===========================================================================
# 5. ROW 3 PANELS
# ===========================================================================
# Panel 3A: Recent Security Alerts (Table, newest first, 10+ rows)
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
                            "columnOrder": ["col_created", "col_rule", "col_sev", "col_user", "col_ip", "col_host", "col_mitre", "col_count"],
                            "columns": {
                                "col_created": make_date_histogram_col("created_at", "Raised At", desc=True),
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
                    {"columnId": "col_created", "isTransposed": False},
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

# Panel 3B: Events by log source (Donut on source from security-events*)
objects.append({
    "id": "events-by-source-donut",
    "type": "lens",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "Events by log source",
        "description": "Normalized event volume grouped by originating source platform",
        "visualizationType": "lnsPie",
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
                "shape": "donut",
                "layers": [
                    {
                        "layerId": "layer_1",
                        "layerType": "data",
                        "primaryGroups": ["col_source"],
                        "metrics": ["col_count"],
                        "numberDisplay": "percent",
                        "categoryDisplay": "default",
                        "legendDisplay": "default",
                        "nestedLegend": False,
                        "colorMapping": LOG_SOURCE_COLOR_MAPPING
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


# ===========================================================================
# 6. ROW 4 PANELS (Lab-required)
# ===========================================================================
# Panel 4A: Top Source IPs (Data Table)
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

# Panel 4B: Hosts with Post-Logon Suspicious Execution (Data Table)
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


# ===========================================================================
# 7. ADDITIONAL PANELS (Used by Alerts & Timeline Dashboards)
# ===========================================================================
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
                        "yConfig": [{"forAccessor": "col_count", "color": CHART_PALETTE[1]}],
                        "color": CHART_PALETTE[1]
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
                        "yConfig": [{"forAccessor": "col_count", "color": CHART_PALETTE[5]}],
                        "color": CHART_PALETTE[5]
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
                        "yConfig": [{"forAccessor": "col_count", "color": CHART_PALETTE[2]}],
                        "color": CHART_PALETTE[2]
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
                        "yConfig": [{"forAccessor": "col_count", "color": CHART_PALETTE[6]}],
                        "color": CHART_PALETTE[6]
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
                                "col_type": make_terms_col("event_type", "Event Type", size=6, order_by_col="col_count"),
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
                        "yConfig": [{"forAccessor": "col_count", "color": CHART_PALETTE[5]}],
                        "color": CHART_PALETTE[5]
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


# ===========================================================================
# 8. DASHBOARDS
# ===========================================================================

# Dashboard 1: SOC Triage Board (Analyst Board Layout)
# Row 1: Four count cards (w=12 each, h=6, y=0)
# Row 2: Row of three (w=16 each, h=12, y=6)
# Row 3: Row of two (Recent Security Alerts w=30, Events by log source w=18, h=14, y=18)
# Row 4: Lab required panels (w=24 each, h=12, y=32)
objects.append({
    "id": "soc-triage-board-dashboard",
    "type": "dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "8.9.0",
    "attributes": {
        "title": "SOC Triage Board",
        "description": "BCSSL Lab 07 - Analyst Triage Board with Unified Metric Counters and Visual Analytics",
        "hits": 0,
        "timeRestore": True,
        "timeFrom": "now-7d",
        "timeTo": "now+1d",
        "refreshInterval": {
            "pause": False,
            "value": 2000
        },
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps([
            # Row 1: 4 Metric cards (y: 0, h: 6, w: 12 each)
            {"version": "8.13.0", "panelIndex": "panel-1", "gridData": {"x": 0, "y": 0, "w": 12, "h": 6, "i": "panel-1"}, "panelRefName": "panel_panel-1"},
            {"version": "8.13.0", "panelIndex": "panel-2", "gridData": {"x": 12, "y": 0, "w": 12, "h": 6, "i": "panel-2"}, "panelRefName": "panel_panel-2"},
            {"version": "8.13.0", "panelIndex": "panel-3", "gridData": {"x": 24, "y": 0, "w": 12, "h": 6, "i": "panel-3"}, "panelRefName": "panel_panel-3"},
            {"version": "8.13.0", "panelIndex": "panel-4", "gridData": {"x": 36, "y": 0, "w": 12, "h": 6, "i": "panel-4"}, "panelRefName": "panel_panel-4"},

            # Row 2: Row of three (y: 6, h: 12, w: 16 each)
            {"version": "8.13.0", "panelIndex": "panel-5", "gridData": {"x": 0, "y": 6, "w": 16, "h": 12, "i": "panel-5"}, "panelRefName": "panel_panel-5"},
            {"version": "8.13.0", "panelIndex": "panel-6", "gridData": {"x": 16, "y": 6, "w": 16, "h": 12, "i": "panel-6"}, "panelRefName": "panel_panel-6"},
            {"version": "8.13.0", "panelIndex": "panel-7", "gridData": {"x": 32, "y": 6, "w": 16, "h": 12, "i": "panel-7"}, "panelRefName": "panel_panel-7"},

            # Row 3: Row of two (y: 18, h: 14)
            {"version": "8.13.0", "panelIndex": "panel-8", "gridData": {"x": 0, "y": 18, "w": 30, "h": 14, "i": "panel-8"}, "panelRefName": "panel_panel-8"},
            {"version": "8.13.0", "panelIndex": "panel-9", "gridData": {"x": 30, "y": 18, "w": 18, "h": 14, "i": "panel-9"}, "panelRefName": "panel_panel-9"},

            # Row 4: Lab required panels (y: 32, h: 12, w: 24 each)
            {"version": "8.13.0", "panelIndex": "panel-10", "gridData": {"x": 0, "y": 32, "w": 24, "h": 12, "i": "panel-10"}, "panelRefName": "panel_panel-10"},
            {"version": "8.13.0", "panelIndex": "panel-11", "gridData": {"x": 24, "y": 32, "w": 24, "h": 12, "i": "panel-11"}, "panelRefName": "panel_panel-11"}
        ]),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"id": "metric-total-alerts", "name": "panel_panel-1", "type": "lens"},
        {"id": "metric-critical-alerts", "name": "panel_panel-2", "type": "lens"},
        {"id": "metric-high-alerts", "name": "panel_panel-3", "type": "lens"},
        {"id": "metric-medium-alerts", "name": "panel_panel-4", "type": "lens"},
        {"id": "alerts-by-severity", "name": "panel_panel-5", "type": "lens"},
        {"id": "event-categories-pie", "name": "panel_panel-6", "type": "lens"},
        {"id": "top-hosts-by-events", "name": "panel_panel-7", "type": "lens"},
        {"id": "recent-alerts-table", "name": "panel_panel-8", "type": "lens"},
        {"id": "events-by-source-donut", "name": "panel_panel-9", "type": "lens"},
        {"id": "top-source-ips", "name": "panel_panel-10", "type": "lens"},
        {"id": "suspicious-execution-hosts", "name": "panel_panel-11", "type": "lens"}
    ]
})

# Dashboard 2: Alerts Dashboard
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
        "refreshInterval": {
            "pause": False,
            "value": 2000
        },
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps([
            {"version": "8.13.0", "panelIndex": "panel-1", "gridData": {"x": 0, "y": 0, "w": 24, "h": 14, "i": "panel-1"}, "panelRefName": "panel_panel-1"},
            {"version": "8.13.0", "panelIndex": "panel-2", "gridData": {"x": 24, "y": 0, "w": 24, "h": 14, "i": "panel-2"}, "panelRefName": "panel_panel-2"},
            {"version": "8.13.0", "panelIndex": "panel-3", "gridData": {"x": 0, "y": 14, "w": 24, "h": 14, "i": "panel-3"}, "panelRefName": "panel_panel-3"},
            {"version": "8.13.0", "panelIndex": "panel-4", "gridData": {"x": 24, "y": 14, "w": 24, "h": 14, "i": "panel-4"}, "panelRefName": "panel_panel-4"},
            {"version": "8.13.0", "panelIndex": "panel-5", "gridData": {"x": 0, "y": 28, "w": 48, "h": 14, "i": "panel-5"}, "panelRefName": "panel_panel-5"},
            {"version": "8.13.0", "panelIndex": "panel-6", "gridData": {"x": 0, "y": 42, "w": 48, "h": 14, "i": "panel-6"}, "panelRefName": "panel_panel-6"}
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

# Dashboard 3: Timeline Analysis Dashboard
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
        "refreshInterval": {
            "pause": False,
            "value": 2000
        },
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "panelsJSON": json.dumps([
            {"version": "8.13.0", "panelIndex": "panel-1", "gridData": {"x": 0, "y": 0, "w": 48, "h": 15, "i": "panel-1"}, "panelRefName": "panel_panel-1"},
            {"version": "8.13.0", "panelIndex": "panel-2", "gridData": {"x": 0, "y": 15, "w": 48, "h": 15, "i": "panel-2"}, "panelRefName": "panel_panel-2"}
        ]),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"id": "timeline-events-over-time", "name": "panel_panel-1", "type": "lens"},
        {"id": "events-by-source-donut", "name": "panel_panel-2", "type": "lens"}
    ]
})

with open(NDJSON_PATH, "w", encoding="utf-8") as f:
    for obj in objects:
        f.write(json.dumps(obj) + "\n")

print(f"Generated {len(objects)} Kibana saved objects into {NDJSON_PATH.name}")
