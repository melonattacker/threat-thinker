from threat_thinker.business_context import (
    dfd_result_from_payload,
    dfd_result_to_sidecar_dict,
)


def test_dfd_result_from_payload_builds_graph_and_sidecar_confidence():
    payload = {
        "summary": "Customers use a web app backed by an API and database.",
        "graph": {
            "zones": {
                "internet": {
                    "id": "internet",
                    "name": "Internet",
                    "confidence": "implied",
                },
                "private": {
                    "id": "private",
                    "name": "Private",
                    "parent_id": "internet",
                    "confidence": "assumed",
                },
            },
            "nodes": {
                "customer": {
                    "id": "customer",
                    "label": "Customer",
                    "type": "actor",
                    "zones": ["internet"],
                    "confidence": "stated",
                },
                "api": {
                    "id": "api",
                    "label": "API",
                    "type": "service",
                    "zones": ["internet", "private"],
                    "data": ["PII"],
                    "auth": True,
                    "confidence": "implied",
                },
            },
            "edges": [
                {
                    "src": "customer",
                    "dst": "api",
                    "label": "uses",
                    "protocol": "HTTPS",
                    "confidence": "implied",
                }
            ],
        },
        "assumptions": ["API is server-side."],
        "clarifying_questions": [],
    }

    result = dfd_result_from_payload(payload)
    sidecar = dfd_result_to_sidecar_dict(result)

    assert result.graph.source_format == "description"
    assert result.graph.nodes["api"].zone == "Private"
    assert result.graph.edges[0].src == "customer"
    assert result.element_confidence["nodes"]["customer"] == "stated"
    assert result.element_confidence["edges"]["customer->api:uses"] == "implied"
    assert sidecar["graph"]["nodes"]["api"]["data"] == ["PII"]
    assert sidecar["assumptions"] == ["API is server-side."]


def test_dfd_result_from_payload_allows_empty_graph_with_questions():
    payload = {
        "summary": "Not enough information.",
        "graph": {"nodes": {}, "edges": [], "zones": {}},
        "assumptions": [],
        "clarifying_questions": ["Who uses the system?"],
    }

    result = dfd_result_from_payload(payload)

    assert result.graph.nodes == {}
    assert result.graph.edges == []
    assert result.clarifying_questions == ["Who uses the system?"]
