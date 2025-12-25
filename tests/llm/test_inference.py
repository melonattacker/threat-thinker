"""
Tests for LLM inference helpers.
"""

import os
import sys

import pytest

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from threat_thinker.llm.inference import _validate_hints_payload


def test_validate_hints_payload_accepts_nodes_only():
    payload = {"nodes": {"A": {"type": "service"}}}
    _validate_hints_payload(payload)


def test_validate_hints_payload_accepts_edges_only():
    payload = {"edges": [{"from": "A", "to": "B", "protocol": "HTTPS"}]}
    _validate_hints_payload(payload)


def test_validate_hints_payload_rejects_non_object_nodes():
    payload = {"nodes": []}
    with pytest.raises(ValueError):
        _validate_hints_payload(payload)


def test_validate_hints_payload_rejects_non_list_edges():
    payload = {"nodes": {}, "edges": {}}
    with pytest.raises(ValueError):
        _validate_hints_payload(payload)
