# Threat Thinker Design

## Purpose
Threat Thinker is designed to make threat modeling lightweight and continuously usable in modern development environments.  
It automatically extracts components, data flows, and trust boundaries from system architecture diagrams and produces a prioritized list of threats with concise explanations and ASVS/CWE references.

## Architecture Overview
Threat Thinker is composed of five major layers:

1. **Parser Layer**  
   Converts diagrams (Mermaid, Draw.io, or image files via LLM vision) into a unified intermediate representation (`Graph` of `Node` and `Edge`). Supports multiple input formats including `.mmd/.mermaid`, `.drawio/.xml`, and image files (`.jpg/.jpeg/.png/.gif/.bmp/.webp`).

2. **Inference Layer (LLM-assisted)**  
   Infers missing attributes such as zone, type, and data sensitivity using a combination of syntax parsing and large language model reasoning. Supports multiple LLM providers (OpenAI, Anthropic, AWS Bedrock).

3. **Threat Generation Layer**  
   Uses LLM-based analysis to enumerate and score threats based on STRIDE categories, providing one-line rationales and references to OWASP ASVS and CWE. Supports multilingual output.

4. **Threat Filtering & Denoising Layer**  
   Applies sophisticated filtering algorithms to remove generic threats, enforce quality thresholds (ASVS references, confidence scores, evidence requirements), eliminate near-duplicates, and rank threats by score and severity.

5. **Reporting Layer**  
   Outputs results as Markdown or JSON and supports incremental updates through diff comparison between versions. Includes Web UI interface powered by Gradio.

## Processing Flow

```
Diagram (.mmd/.mermaid, .drawio/.xml, or image files)
↓
[Parser] → Graph(nodes, edges) + ImportMetrics
↓
[LLM Attribute Inference] (optional, multilingual)
↓
[User Hints Application] (optional YAML override)
↓
[LLM Threat Generation] (multilingual)
↓
[Threat Filtering & Denoising]
↓
[Export] → Markdown / JSON / Diff
```

## Key Technical Concepts
- **Multi-Format Support:** Supports Mermaid diagrams, Draw.io files, and image-based architecture diagrams using LLM vision capabilities.  
- **Multilingual Support:** Both hint inference and threat generation support multiple languages through ISO language codes.  
- **Multiple LLM Providers:** Supports OpenAI, Anthropic, and AWS Bedrock APIs with flexible configuration.  
- **Hybrid Parsing:** Combines static syntax parsing with LLM completion to improve structure accuracy and reduce noise.  
- **Low-Noise Threat Extraction:** Advanced filtering and denoising algorithms remove generalized findings and focus on diagram-specific risks through multiple quality gates including ASVS reference requirements, confidence thresholds, evidence validation, and near-duplicate detection.  
- **Explainable Output:** Every threat includes a one-line reason and references to ASVS or CWE, plus evidence nodes/edges.  
- **Incremental Analysis:** Supports differential updates when diagrams change.  
- **Dual Interface:** CLI-based tool for automation and Gradio Web UI for interactive use.  
- **Import Metrics:** Tracks parsing success rates and provides feedback on diagram interpretation quality.
