# Hint YAML Guide

## What Are Hints?
`hint.yaml` lets you describe system attributes that diagrams might omit or that you want to override. Hints travel with your diagram and are applied before threat generation so the model has the right context (zones, protocols, data sensitivity, auth expectations, etc.).

Processing order:
1. Parse the diagram into a graph (nodes + edges).
2. Optionally infer attributes with LLM (`--infer-hints`).
3. Apply your `--hints hint.yaml` file. Your hints win over inferred ones and can add missing nodes/edges.

## When to Use
- The diagram lacks zones, data classifications, or protocols and you want deterministic inputs.
- You need to override LLM-inferred attributes (e.g., a service is private even if named "gateway").
- You want to add non-visual components such as logging or IAM layers to anchor threats.

## File Structure
Top-level keys:
- `nodes`: map of node IDs → attributes.
- `edges`: list of edges (`from`/`to`) with attributes.

### Nodes
Each entry key should match the node ID from the diagram. Attributes:
- `label` (string): display name.
- `type` (string): e.g., `actor`, `service`, `database`, `queue`, `cache`, `lambda`, `elb`, `ingress`, `pod`, `s3`, `unknown`.
- `zone` (string): e.g., `Internet`, `DMZ`, `Private`, `K8s-Namespace`, `VPC-Public`, `VPC-Private`, `AWS-Managed`, `unknown`.
- `data` (list): values like `PII`, `Credentials`, `Internal`, `Secrets`.
- `auth` (bool): whether the component enforces authentication.
- `notes` (string): freeform clarifications.

### Edges
Each edge is an object with:
- `from` / `to` (string): node IDs.
- `protocol` (string): e.g., `HTTP`, `HTTPS`, `TCP`, `gRPC`, `AMQP`, `unknown`.
- `data` (list): classifications moving across the edge (`PII`, `Credentials`, `Internal`, `Secrets`).
- `label` (string, optional): custom display label.

If an edge is missing from the parsed diagram, providing it in hints will add it. If it exists, the hint updates protocol/data/label.

## Example
Minimal `hint.yaml` for a 3-tier web app:

```yaml
nodes:
  user: {label: "User", type: actor, zone: Internet}
  api:  {label: "API Gateway", type: service, zone: DMZ, auth: false}
  app:  {label: "App Service", type: service, zone: Private}
  db:   {label: "Customer DB", type: database, zone: Private, data: [PII]}

edges:
  - {from: user, to: api, protocol: HTTPS, data: [Credentials]}
  - {from: api,  to: app, protocol: HTTP}
  - {from: app,  to: db,  protocol: TCP, data: [PII]}
```

See `examples/web/hint.yaml` and `examples/aws/hint.yaml` for more complex layouts.

## CLI and Web UI
- CLI: `threat-thinker think --mermaid diagram.mmd --hints hint.yaml --llm-api openai --llm-model gpt-4.1 --out-dir reports/`
- Combine with inference: add `--infer-hints` to let the LLM propose attributes and then override with your `hint.yaml` where needed.
- Web UI: paste YAML into **Hints YAML (optional)**; enable **Infer hints with LLM** to merge inferred attributes before your overrides are applied.

## Tips
- Keep node IDs stable between diagram and hints to avoid duplicates; use `label` for human-friendly names.
- Specify protocols and data classifications on edges; they drive higher-signal threats and ASVS mapping.
- Use `notes` to capture assumptions (e.g., "API enforces OAuth2 via IdP"), which can steer threat explanations.
- Store hint files near diagrams and version them with architecture changes to keep threat models reproducible.
