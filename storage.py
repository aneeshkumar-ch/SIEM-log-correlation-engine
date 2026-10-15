import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import copy
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk as es_bulk
import config

logger = logging.getLogger(__name__)

# Schema mappings for Elasticsearch 8.x
EVENTS_MAPPING = {
    "properties": {
        "timestamp": {"type": "date"},
        "source": {"type": "keyword"},
        "source_type": {"type": "keyword"},  # compatibility
        "event_type": {"type": "keyword"},
        "user": {"type": "keyword"},
        "source_ip": {"type": "ip"},
        "src_ip": {"type": "keyword"},       # compatibility string
        "destination_ip": {"type": "ip"},
        "dest_ip": {"type": "keyword"},      # compatibility string
        "destination_port": {"type": "integer"},
        "process_name": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "host": {"type": "keyword"},
        "raw_log": {"type": "text"},
        "raw": {"type": "text"},              # compatibility text
        "ip_tags": {"type": "keyword"},
        "action": {"type": "keyword"},
        "file_path": {"type": "keyword"},
        "parent_process": {"type": "keyword"}
    }
}

ALERTS_MAPPING = {
    "properties": {
        "rule_name": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "source_ip": {"type": "ip"},
        "src_ip": {"type": "keyword"},       # compatibility string
        "destination_ip": {"type": "ip"},
        "user": {"type": "keyword"},
        "host": {"type": "keyword"},
        "evidence": {"type": "keyword"},
        "first_seen": {"type": "date"},
        "last_seen": {"type": "date"},
        "mitre_technique": {"type": "keyword"},
        "description": {"type": "text"},
        "created_at": {"type": "date"}
    }
}


class MockIndicesClient:
    """Mock indices namespace matching elasticsearch.client.IndicesClient."""
    def __init__(self, storage: "MockElasticsearch"):
        self._storage = storage

    def exists(self, index: str) -> bool:
        return index in self._storage.indices_data

    def create(self, index: str, mappings: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        if index not in self._storage.indices_data:
            self._storage.indices_data[index] = {}
        return {"acknowledged": True, "shards_acknowledged": True, "index": index}

    def delete(self, index: str, ignore_unavailable: bool = True, **kwargs) -> Dict[str, Any]:
        if index in self._storage.indices_data:
            del self._storage.indices_data[index]
            return {"acknowledged": True}
        if ignore_unavailable:
            return {"acknowledged": True}
        raise KeyError(f"Index {index} does not exist")

    def refresh(self, index: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return {"_shards": {"total": 1, "successful": 1, "failed": 0}}


class MockElasticsearch:
    """In-memory Elasticsearch mock for local testing without Docker.
    Supports deterministic doc indexing by _id, bulk upsert, queries, filtering, sorting, and counts.
    """
    def __init__(self):
        # Format: {index_name: {doc_id: doc_dict}}
        self.indices_data: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.indices = MockIndicesClient(self)

    def ping(self) -> bool:
        return True

    def info(self) -> Dict[str, Any]:
        return {
            "name": "mock-elasticsearch-node",
            "cluster_name": "mock-siem-cluster",
            "version": {"number": "8.13.0"}
        }

    def index(self, index: str, id: str, document: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        if index not in self.indices_data:
            self.indices_data[index] = {}
        self.indices_data[index][id] = copy.deepcopy(document)
        return {"_index": index, "_id": id, "result": "created"}

    def bulk(self, operations: List[Dict[str, Any]], refresh: bool = True, **kwargs) -> Dict[str, Any]:
        # Handle ES bulk format: alternating action dict and source dict,
        # or list of actions with embedded documents.
        items = []
        i = 0
        while i < len(operations):
            op = operations[i]
            action_type = list(op.keys())[0] if op else None
            meta = op.get(action_type, {})
            idx = meta.get("_index")
            doc_id = meta.get("_id")

            if "doc" in meta:
                doc_body = meta["doc"]
                i += 1
            elif "_source" in meta:
                doc_body = meta["_source"]
                i += 1
            elif i + 1 < len(operations) and not any(k in operations[i+1] for k in ("index", "create", "update", "delete")):
                doc_body = operations[i+1]
                i += 2
            else:
                doc_body = meta
                i += 1

            if idx and doc_id:
                if idx not in self.indices_data:
                    self.indices_data[idx] = {}
                self.indices_data[idx][doc_id] = copy.deepcopy(doc_body)
                items.append({action_type: {"_index": idx, "_id": doc_id, "status": 200, "result": "created"}})

        return {"errors": False, "items": items}

    def search(self, index: str, query: Optional[Dict[str, Any]] = None,
               sort: Optional[List[Any]] = None, size: int = 10000, **kwargs) -> Dict[str, Any]:
        if index not in self.indices_data:
            return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}

        all_docs = []
        for doc_id, doc_body in self.indices_data[index].items():
            if self._matches_query(doc_body, query):
                all_docs.append({
                    "_index": index,
                    "_id": doc_id,
                    "_source": copy.deepcopy(doc_body)
                })

        # Apply sorting
        if sort:
            for s in reversed(sort):
                if isinstance(s, dict):
                    field = list(s.keys())[0]
                    order = s[field].get("order", "asc") if isinstance(s[field], dict) else "asc"
                elif isinstance(s, str):
                    field = s
                    order = "asc"
                else:
                    continue
                reverse = (order == "desc")
                all_docs.sort(key=lambda item: str(item["_source"].get(field, "")), reverse=reverse)

        selected = all_docs[:size]
        return {
            "hits": {
                "total": {"value": len(all_docs), "relation": "eq"},
                "hits": selected
            }
        }

    def count(self, index: str, query: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        res = self.search(index=index, query=query, size=10000)
        return {"count": res["hits"]["total"]["value"]}

    def delete_by_query(self, index: str, query: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        if index not in self.indices_data:
            return {"deleted": 0}
        to_delete = []
        for doc_id, doc_body in self.indices_data[index].items():
            if self._matches_query(doc_body, query):
                to_delete.append(doc_id)
        for doc_id in to_delete:
            del self.indices_data[index][doc_id]
        return {"deleted": len(to_delete)}

    def _matches_query(self, doc: Dict[str, Any], query: Optional[Dict[str, Any]]) -> bool:
        if not query or query.get("match_all") == {}:
            return True

        # Bool query
        if "bool" in query:
            bool_q = query["bool"]
            for cond in bool_q.get("must", []):
                if not self._matches_query(doc, cond):
                    return False
            for cond in bool_q.get("filter", []):
                if not self._matches_query(doc, cond):
                    return False
            for cond in bool_q.get("must_not", []):
                if self._matches_query(doc, cond):
                    return False
            shoulds = bool_q.get("should", [])
            if shoulds and not bool_q.get("must") and not bool_q.get("filter"):
                if not any(self._matches_query(doc, cond) for cond in shoulds):
                    return False
            return True

        # Term query
        if "term" in query:
            for field, expected in query["term"].items():
                expected_val = expected.get("value") if isinstance(expected, dict) else expected
                actual_val = doc.get(field)
                if actual_val is None and field == "src_ip":
                    actual_val = doc.get("source_ip")
                elif actual_val is None and field == "source_ip":
                    actual_val = doc.get("src_ip")
                if isinstance(actual_val, list):
                    if str(expected_val) not in [str(x) for x in actual_val]:
                        return False
                elif str(actual_val) != str(expected_val):
                    return False
            return True

        # Terms query
        if "terms" in query:
            for field, expected_list in query["terms"].items():
                actual_val = doc.get(field)
                if isinstance(actual_val, list):
                    if not any(str(x) in [str(y) for y in expected_list] for x in actual_val):
                        return False
                elif str(actual_val) not in [str(x) for x in expected_list]:
                    return False
            return True

        # Range query
        if "range" in query:
            for field, bounds in query["range"].items():
                actual_val = doc.get(field)
                if actual_val is None:
                    return False
                # Date or numeric comparison
                if "gte" in bounds and str(actual_val) < str(bounds["gte"]):
                    return False
                if "gt" in bounds and str(actual_val) <= str(bounds["gt"]):
                    return False
                if "lte" in bounds and str(actual_val) > str(bounds["lte"]):
                    return False
                if "lt" in bounds and str(actual_val) >= str(bounds["lt"]):
                    return False
            return True

        return True


# Global mock singleton instance for test continuity
_mock_instance = MockElasticsearch()


def get_es_client(use_mock: Optional[bool] = None) -> Any:
    """Return an Elasticsearch client instance.
    Uses MockElasticsearch if use_mock is True or config.USE_MOCK_ES is True.
    Otherwise connects to the real Elasticsearch server at config.ES_HOST.
    If real ES is offline, falls back to MockElasticsearch so the dashboard remains active.
    """
    should_use_mock = use_mock if use_mock is not None else config.USE_MOCK_ES
    if should_use_mock:
        return _mock_instance

    # Real Elasticsearch client
    try:
        client = Elasticsearch(
            config.ES_HOST,
            verify_certs=False,
            request_timeout=30
        )
        if client.ping():
            return client
    except Exception:
        pass

    # Fallback to mock when Docker ES is not yet running
    return _mock_instance


import ipaddress


def sanitize_doc_ips(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize IP fields so Elasticsearch ip mapping does not reject invalid strings."""
    cleaned = copy.deepcopy(doc)
    for ip_field in ("source_ip", "destination_ip"):
        val = cleaned.get(ip_field)
        if val is not None:
            val_str = str(val).strip()
            if not val_str or val_str in ("-", "unknown", "none"):
                cleaned[ip_field] = None
            else:
                try:
                    ipaddress.ip_address(val_str)
                    cleaned[ip_field] = val_str
                except ValueError:
                    cleaned[ip_field] = None
    return cleaned


def initialize_indices(es: Any, events_index: str = config.INDEX_EVENTS, alerts_index: str = config.INDEX_ALERTS) -> None:
    """Ensure security-events and security-alerts indices exist with mappings and are refreshed."""
    try:
        if not es.indices.exists(index=events_index):
            es.indices.create(index=events_index, mappings=EVENTS_MAPPING)
            logger.info("Created index %s", events_index)
        es.indices.refresh(index=events_index)
    except Exception as e:
        logger.warning("Could not create/verify index %s: %s", events_index, e)

    try:
        if not es.indices.exists(index=alerts_index):
            es.indices.create(index=alerts_index, mappings=ALERTS_MAPPING)
            logger.info("Created index %s", alerts_index)
        es.indices.refresh(index=alerts_index)
    except Exception as e:
        logger.warning("Could not create/verify index %s: %s", alerts_index, e)



def bulk_index_events(es: Any, documents: List[Dict[str, Any]], index_name: str) -> int:
    """Bulk index documents into Elasticsearch with deterministic _id.
    Each item in documents must contain '_id' and '_source'.
    Returns number of indexed documents.
    """
    if not documents:
        return 0

    sanitized_docs = [
        {"_id": doc["_id"], "_source": sanitize_doc_ips(doc["_source"])}
        for doc in documents
    ]

    if isinstance(es, MockElasticsearch):
        # Mock bulk
        operations = []
        for doc in sanitized_docs:
            operations.append({"index": {"_index": index_name, "_id": doc["_id"]}})
            operations.append(doc["_source"])
        es.bulk(operations=operations)
        return len(sanitized_docs)

    # Real Elasticsearch bulk
    actions = [
        {
            "_index": index_name,
            "_id": doc["_id"],
            "_source": doc["_source"]
        }
        for doc in sanitized_docs
    ]
    success_count, _ = es_bulk(es, actions, refresh=True)
    return success_count
