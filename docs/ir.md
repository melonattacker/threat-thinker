# Native IR Guide

Threat Thinker can accept its native intermediate representation (IR) directly.

This IR is the JSON form of the existing internal `Graph` model:
- `nodes`: object keyed by node id
- `edges`: array of edges
- `zones`: object keyed by zone id

Use native IR when another tool already knows your architecture structure and you want to skip Mermaid/Draw.io parsing.

## When to Use It
- You already have a system model from another tool or pipeline
- You want a stable machine-generated input format
- You want to feed Threat Thinker without diagram syntax

Use Mermaid/Draw.io/Threat Dragon instead when humans are authoring the input manually.

## How to Run

CLI:

```bash
threat-thinker think \
    --ir examples/diagrams/ir/system.ir.json \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir reports/
```

Notes:
- Use `--ir` explicitly. Native IR is not auto-detected via `--diagram`.
- JSON autodetection remains reserved for Threat Dragon v2 compatibility.

## Top-Level Shape

```json
{
  "nodes": {},
  "edges": [],
  "zones": {}
}
```

Optional top-level fields:
- `source_format`: ignored on input; Threat Thinker normalizes it to `ir`

Not supported for native IR input:
- `threat_dragon`

If you need Threat Dragon layout-preserving round-trip, use `--threat-dragon` instead of native IR.

## Nodes

`nodes` must be an object keyed by node id.

```json
{
  "nodes": {
    "api": {
      "id": "api",
      "label": "API",
      "type": "service",
      "zones": ["internet", "dmz"],
      "data": ["PII"],
      "auth": true,
      "notes": "Internet-facing application API"
    }
  }
}
```

Fields:
- `id`: required, non-empty, must match the object key
- `label`: required, non-empty
- `type`: optional string such as `actor`, `service`, `store`, `queue`, `cache`
- `zones`: optional array of zone ids, ordered outer -> inner
- `zone`: optional legacy single-zone field; if `zones` is present, Threat Thinker will normalize `zone` to the innermost representative zone name
- `data`: optional array of data classes such as `PII`, `Secrets`, `Credentials`
- `auth`: optional boolean
- `notes`: optional string

## Edges

`edges` must be an array.

```json
{
  "edges": [
    {
      "id": "edge-1",
      "src": "user",
      "dst": "api",
      "label": "HTTPS",
      "protocol": "HTTPS",
      "data": ["Credentials"]
    }
  ]
}
```

Fields:
- `src`: required node id
- `dst`: required node id
- `label`: optional string
- `protocol`: optional string such as `HTTP`, `HTTPS`, `TLS`, `gRPC`, `TCP`
- `data`: optional array of data classes carried on the edge
- `id`: optional stable edge id

Validation rules:
- `src` and `dst` must reference existing node ids

## Zones

`zones` must be an object keyed by zone id.

```json
{
  "zones": {
    "internet": {
      "id": "internet",
      "name": "Internet"
    },
    "dmz": {
      "id": "dmz",
      "name": "DMZ",
      "parent_id": "internet"
    }
  }
}
```

Fields:
- `id`: required, non-empty, must match the object key
- `name`: required, non-empty
- `parent_id`: optional parent zone id

Validation rules:
- `parent_id` must reference an existing zone
- zone hierarchies must be acyclic
- node `zones` entries must reference existing zone ids

## Minimal Example

```json
{
  "nodes": {
    "user": {
      "id": "user",
      "label": "User",
      "type": "actor",
      "zones": ["internet"]
    },
    "api": {
      "id": "api",
      "label": "API",
      "type": "service",
      "zones": ["internet", "dmz"],
      "auth": true
    },
    "db": {
      "id": "db",
      "label": "Database",
      "type": "store",
      "zones": ["internet", "dmz", "private"],
      "data": ["PII"]
    }
  },
  "edges": [
    {
      "src": "user",
      "dst": "api",
      "label": "HTTPS",
      "protocol": "HTTPS"
    },
    {
      "src": "api",
      "dst": "db",
      "label": "SQL",
      "protocol": "TLS"
    }
  ],
  "zones": {
    "internet": {
      "id": "internet",
      "name": "Internet"
    },
    "dmz": {
      "id": "dmz",
      "name": "DMZ",
      "parent_id": "internet"
    },
    "private": {
      "id": "private",
      "name": "Private",
      "parent_id": "dmz"
    }
  }
}
```

See also:
- Example file: [`examples/diagrams/ir/system.ir.json`](../examples/diagrams/ir/system.ir.json)

## API and Web UI

API:
- Set `input.type` to `ir`
- Put the JSON text in `input.content`

Multipart API:
- Upload the JSON file
- Set form field `type=ir`

Web UI:
- Choose `Text`
- Choose format `ir`
- Paste the native IR JSON

## Common Validation Errors

- `IR payload must be a JSON object.`
  - Top-level JSON was an array or scalar.
- `Node key 'x' does not match embedded id 'y'.`
  - The object key and `id` field differ.
- `Edge at index N references unknown nodes 'a' -> 'b'.`
  - `src` or `dst` does not exist in `nodes`.
- `Node 'api' references unknown zone 'dmz'.`
  - A zone id listed in `zones` is missing from top-level `zones`.
- `Zone hierarchy contains a cycle`
  - Parent references loop back.
- `IR input does not support threat_dragon metadata`
  - Native IR is not the same as Threat Dragon import/export metadata.

## Design Notes

- Native IR is the formal internal input shape for Threat Thinker analysis.
- Existing Mermaid/Draw.io/Threat Dragon/image flows still normalize into the same `Graph`.
- Native IR is explicit-only in v1 to avoid ambiguity with Threat Dragon JSON.
