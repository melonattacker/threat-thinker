# Threat Thinker
<img width="360" height="150" alt="threat-thinker-logo" src="https://github.com/user-attachments/assets/78524431-4d48-4fb7-b69d-4b83856b620d" />


**Threat Thinker** is an open-source tool that automatically performs **threat modeling from system architecture diagrams**.  

It analyzes diagrams written in **Mermaid**, **draw.io**, or extracted from **images** to identify **components**, **data flows**, and **trust boundaries** using a **hybrid of syntax parsing and LLM reasoning**. The tool then generates a **prioritized list of potential threats** with concise explanations and references to standards like **OWASP ASVS** and **CWE**.  

Designed for **simplicity** and **low noise**, Threat Thinker enables teams to keep their **threat models up to date** with minimal manual effort.

https://github.com/user-attachments/assets/4b1ded1c-36fc-4834-ade3-196db1af550f

## Getting Started
### Set Up API Keys
Threat Thinker uses LLM for extracting diagrams from images, extracting components, data flows, and trust boundaries from architecture diagrams, and for inferring threats.

Threat Thinker supports OpenAI, Anthropic Claude and AWS Bedrock(only claude v3 or newer model) APIs.

You must set at least one of the following environment variables before use:

```bash
# For OpenAI API (e.g., gpt-4.1)
export OPENAI_API_KEY=...

# For Claude API (e.g., claude-sonnet-4-5)
export ANTHROPIC_API_KEY=...

# For Bedrock API (e.g., anthropic.claude-sonnet-4-5-20250929-v1:0)
# Option 1: Use AWS Profile (recommended)
aws configure --profile my-profile
# Then use --aws-profile my-profile in the command

# Option 2: Use environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

### Installation

```bash
git clone https://github.com/melonattacker/threat-thinker.git
cd threat-thinker
pip install -e . -r requirements.txt

# If using uv
uv venv
source .venv/bin/activate
uv pip install -e . -r requirements.txt
```

### CLI Usage
Here is an example of command using CLI mode.


```bash
# Think: Analyze a mermaid diagram
threat-thinker think \
    --mermaid examples/web/system.mmd \
    --infer-hints \
    --topn 5 \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir reports/

# Think: Analyze a draw.io diagram
threat-thinker think \
    --drawio examples/web/system.xml \
    --infer-hints \
    --topn 5 \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir reports/

# Think: Analyze a image diagram
threat-thinker think \
    --image examples/web/system.png \
    --infer-hints \
    --topn 5 \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir reports/

# Diff: Compare two threat reports and analyze changes
threat-thinker diff \
    --after reports/new-report.json \
    --before reports/old-report.json \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir reports/ \
    --lang en
```

### Local Knowledge Base (Optional RAG)
Threat Thinker can enrich LLM reasoning with locally stored guidance (OWASP, MITRE, internal standards, etc.).

1. Place PDF/HTML/Markdown/Text documents under `~/.threat-thinker/kb/<kb_name>/raw/`.
2. Build embeddings with OpenAI:  
   ```bash
   threat-thinker kb build <kb_name> \
       --embedder openai:text-embedding-3-small \
       --chunk-tokens 800 --chunk-overlap 80
   ```
3. Inspect or search the KB:  
   ```bash
   threat-thinker kb list
   threat-thinker kb search <kb_name> "lateral movement" --topk 5 --show
   ```
4. Use the KB during analysis:  
   ```bash
   threat-thinker think --mermaid diagram.mmd --rag --kb <kb_name> \
       --rag-topk 8 --llm-api openai --llm-model gpt-4.1
   ```

### Web UI

```bash
# Launch Web UI
threat-thinker webui
```

Then visit http://localhost:7860 to use Threat Thinker interactively:

- Input diagram as text or upload an image file
- Build a local knowledge base from the **Knowledge Base** tab (upload PDF/Markdown/Text/HTML), then refresh the list
- Enable **Use Knowledge Base (local RAG)** on the Think tab, pick one or more KBs, and set RAG top-k
- Choose models & settings
- Generate a prioritized list of potential threats

Here is the demo screen for the Web UI.

## Tutorials
You can see examples of using Threat Thinker to analyze potential threats of several system architecture diagrams.

[docs/tutorials.md](./docs/tutorials.md)

## Design & Architecture
Learn about Threat Thinker's 5-layer architecture, processing flow, and key technical concepts.

[docs/design.md](./docs/design.md)

## Hint YAML (manual overrides)
Provide zones, protocols, data classifications, and other attributes alongside your diagrams so Threat Thinker generates threats with the right context. See [docs/hints.md](./docs/hints.md) for concepts, schema, and examples.

## Reports (Markdown / JSON / HTML)
Threat Thinker emits three report formats per run. See [docs/reports.md](./docs/reports.md) for what each format contains and when to use it.
