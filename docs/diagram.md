# Diagram Authoring Tips

Practical notes for crafting diagrams that Threat Thinker can parse cleanly. These tips mirror the current Mermaid/Draw.io/Threat Dragon parsers so you get predictable nodes, edges, and trust boundaries without heavy hinting.

## Common Principles
- Use stable node IDs; keep human-friendly names in labels. Directional arrows determine source/destination.
- Prefer explicit labels on edges (protocol, data type) and on boundaries (zone name) rather than relying on styling.
- Keep components fully inside a trust boundary box so the parser can associate them via geometry.
- If your diagram already encodes zones/boundaries and component roles, skip `--infer-hints` to avoid the LLM overwriting intentional placements.

## Mermaid
- **Nodes**: `nodeId[Label]`, `nodeId((Label))`, or plain `nodeId` are all accepted. IDs allow letters, numbers, `_`, `-`, `.`.
- **Edges**: Any of `A -> B`, `A --> B`, `A -- label --> B`, or `A --> B |label|` are parsed. Inline `[Label]` after the source is ignored for the edge direction.
- **Trust boundaries**: Use `subgraph Boundary Name` … `end`. Nested subgraphs become nested zones; the innermost containing subgraphs are attached to each node.
- **Keep it deterministic**: Avoid Mermaid features that do not emit `subgraph` blocks or `--` arrows (e.g., flowcharts with implicit direction) because the parser only reads explicit edges and subgraphs.

## Draw.io
- **Nodes**: Any non-edge `mxCell` with a label becomes a node; IDs are taken from the cell ID. Default cells `0`/`1` are ignored.
- **Edges**: Use connectors with `source` and `target` set; labels are taken from the edge text or attached `edgeLabel` cells.
- **Trust boundaries**: Dashed/dotted rectangles with a label are treated as zones. Shapes with `rectangle`, `shape=rect`, or `rounded=1` plus hints like `dashed=1`, `dashpattern`, `boundary`, `zone`, or `trust` in the style are detected.
- **Placement**: The parser looks at element centers; keep nodes fully inside boundary rectangles (including nested rectangles) so containment is unambiguous.

## Threat Dragon (v2 JSON)
- **Nodes**: Supported `data.type` values are `tm.Actor`, `tm.Process`, and `tm.Store`. Labels come from `data.name`, `attrs.text`, or `attrs.label`.
- **Edges**: Flows use cells where `data.type` is `tm.Flow` and `shape` is `flow`. Direction follows `source.cell` → `target.cell`; labels come from `data.name` or the first entry in `labels`.
- **Trust boundaries**: Cells with `shape` of `trust-boundary-box` or `data.type` of `tm.BoundaryBox`/`tm.boundary` become zones. Size/position drives containment; place nodes fully inside to avoid misassignment.
- **Version check**: Keep exports in the 2.x model format; older/newer layouts may parse but will lose fidelity.

## Screenshots / Raster Images
- **Source format**: PNG/JPEG/GIF/BMP/WEBP are supported, but text must be legible. Prefer high-resolution captures or exports instead of photos of screens.
- **What is detected**: Nodes, labeled edges, and trust boundary rectangles if they are clearly drawn. The parser relies on an LLM image call; you need a configured `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/Bedrock credentials.
- **Consistency tips**: Use straight arrows with visible arrowheads, keep labels horizontal, and avoid crowded overlaps. Draw boundary boxes with solid/dashed outlines and readable titles.
- **Determinism**: Image parsing is best-effort and less repeatable than Mermaid/Draw.io/Threat Dragon. If you need stable results, keep a vector diagram and feed that instead.

## When to Skip `--infer-hints`
`--infer-hints` asks the LLM to guess node types, protocols, and zones. Use it when diagrams are thin on detail. Omit it when:
- Your diagram already encodes trust boundaries/zones correctly (Mermaid subgraphs, Draw.io boundary boxes, Threat Dragon boundary cells).
- You’ve labeled edges with protocols or data classifications and want to keep those exact values.
- Determinism matters (CI snapshots, golden files) and you don’t want LLM variance.

If you do combine inference with hand-authored hints, remember your `hint.yaml` overrides the inferred values. Keep node IDs consistent between the diagram and hints to avoid duplicates.
