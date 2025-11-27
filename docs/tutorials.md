# Tutorials
## Tutorial 1: Analyze simple web application
In this example, we will analyze the architecture diagram of a simple web application.  written in mermaid and identify potential threats.

### What This Does
- Analyzes a simple 3-tier web application architecture with User → API Gateway → App Service → Database flow
- Uses Mermaid diagram format to parse the system components and data flows
- Automatically infers potential security hints and generates the top 5 highest-priority threats
- Applies STRIDE methodology to identify threats across spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege
- Outputs results in Markdown/JSON/HTML with detailed threat descriptions, affected components, and security references

### Diagram

![web](../examples/web/system.png)

### Command

```bash
threat-thinker think \
    --mermaid examples/web/system.mmd \
    --infer-hints \
    --topn 5 \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir examples/web/reports/
```
You can optionally set `--out-name` if you want to override the base report filename.

### Discovered potential threats
| ID | Threat | Severity | Score |
|----|---------|---------|-------|
| T001 | Exposure of Sensitive Data in Transit | High | 8.0 |
| T002 | Potential Lack of Input Validation on API | High | 8.0 |
| T003 | Unencrypted Internal API Communication | High | 8.0 |
| T004 | Denial of Service via Unauthenticated API Access | Medium | 6.0 |
| T005 | Insufficient Authentication on Internal Services | Medium | 6.0 |

- [Markdown Report](../examples/web/reports/system_report.md)
- [JSON Report](../examples/web/reports/system_report.json)
- [HTML Report](../examples/web/reports/system_report.html)

### What Was Discovered
The analysis identified 5 threats in this simple web application:

**High Severity Threats:**
- **Exposure of Sensitive Data in Transit (app → db)**: TCP without encryption could leak data if the network is compromised.
- **Potential Lack of Input Validation on API**: Internet-facing API may be vulnerable to injection without strong validation.
- **Unencrypted Internal API Communication (api → app)**: HTTP inside DMZ/Private risks interception/tampering.

**Medium Severity Threats:**
- **Denial of Service via Unauthenticated API Access**: Missing rate limiting/auth could allow request floods.
- **Insufficient Authentication on Internal Services (app/db)**: Weak service-to-service auth enables lateral impersonation.

## Tutorial 2: Analyze AWS system
In this example, we analyze the architecture diagram of the AWS-based system shown in the screenshot to identify potential threats.

### What This Does
- Analyzes a complex AWS cloud architecture from an image/screenshot rather than a text-based diagram
- Processes a multi-tier system including CloudFront, Load Balancer, ECS Fargate, Aurora RDS, S3, SQS, SNS, and Lambda
- Uses the `--require-asvs` flag to ensure all threats are mapped to OWASP Application Security Verification Standard (ASVS) requirements
- Generates the top 10 most critical threats with detailed scoring and evidence
- Demonstrates image-based analysis capabilities for existing architecture documentation

### Diagram

![aws](../examples/aws/system.png)

### Command

```bash
threat-thinker think \
    --image examples/aws/system.png \
    --infer-hints \
    --require-asvs \
    --topn 10 \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir examples/aws/reports/
```

### Discovered potential threats

| ID | Threat | Severity | Score |
|----|---------|---------|-------|
| T001 | Potential Credential Theft at Ingress Point | High | 8.0 |
| T002 | Unencrypted Traffic Between Load Balancer and ECS Service Exposes Sensitive Data | High | 8.0 |
| T003 | Lack of End-to-End Encryption for PII to Database | High | 7.0 |
| T004 | Exposure of Internal Data via S3 Bucket Misconfiguration | Medium | 6.0 |
| T005 | Insufficient Authentication Between Internal Services | Medium | 6.0 |
| T006 | Denial of Service Risk at Public Ingress Points | Medium | 5.0 |
| T007 | Insufficient Access Controls on Internal AWS Resources | Medium | 5.0 |
| T008 | Lack of Audit Logging for Sensitive Operations | Medium | 5.0 |
| T009 | Potential for Message Tampering or Replay in SQS/SNS | Medium | 5.0 |
| T010 | Lack of Input Validation on User-Provided Data | Low | 3.0 |

- [Markdown Report](../examples/aws/reports/system_report.md)
- [JSON Report](../examples/aws/reports/system_report.json)
- [HTML Report](../examples/aws/reports/system_report.html)

### What Was Discovered
The AWS architecture analysis revealed 10 threats:

**High Severity Threats:**
- **Potential Credential Theft at Ingress (User → CloudFront)**: Misconfigured HTTPS could expose credentials.
- **Unencrypted Traffic Between ALB and ECS**: HTTP inside the VPC exposes PII/internal data.
- **Lack of End-to-End Encryption for PII to Database**: TCP to RDS may be unencrypted.

**Medium/Low Severity Threats:**
- **S3 Bucket Misconfiguration**: Internal data could leak via permissive policies.
- **Insufficient Authentication Between Internal Services**: ALB ↔ ECS not authenticated.
- **DoS Risk at Public Ingress Points**: CloudFront/ALB need WAF/rate limits.
- **Insufficient Access Controls on AWS Resources**: Overly permissive IAM on S3/SQS/SNS/RDS.
- **Lack of Audit Logging**: Missing audit trails on ECS/RDS/S3.
- **Message Tampering/Replay in SQS/SNS**: Integrity/auth not enforced.
- **Lack of Input Validation on User Data**: ECS endpoints may be exploitable without validation.

## Tutorial 3: Analyze the difference between before and after reports
In this example, we will analyze the differences between the threat analysis results for an updated web application diagram and those for the previous version of the diagram.

### What This Does
- Compares threat analysis results between two different system architectures to identify security improvements and new risks
- Analyzes the security impact of architectural changes by examining added/removed components and data flows
- Uses the `diff` command to automatically generate comprehensive change analysis reports
- Demonstrates how security posture changes when defensive controls (WAF, logging, monitoring) are added to a system
- Provides recommendations for addressing new risks introduced by architectural modifications
- Shows both positive security implications and potential new attack surfaces created by system evolution

### Diagram

#### Before
![before](../examples/web/system.png)

#### After
![after](../examples/web/system-updated.png)

### Command

```bash
threat-thinker diff \
    --after examples/web/reports/system-updated_report.json \
    --before examples/web/reports/system_report.json \
    --llm-api openai \
    --llm-model gpt-4.1 \
    --out-dir examples/web/reports/ \
    --out-name diff \
    --lang en
```

- [Markdown Report](../examples/web/reports/diff.md)
- [JSON Report](../examples/web/reports/diff.json)

### What Was Discovered
The diff shows major architecture changes but no documented threat changes:

- **Graph changes:** Added WAF, cache, logging, analytics, monitoring, and alerting nodes; user now routes through WAF; added logging/monitoring flows; removed direct user → api edge.
- **Threat changes:** None recorded (0 added/removed), highlighting a gap—threats were not updated for the new components.
- **Impact:** Security posture likely improves (WAF, observability, cache) but new components add attack surface and must be hardened (WAF rules, log protection, cache security).
- **Recommendation:** Update the threat model to include new nodes/edges and assess threats specific to WAF, cache, logging/analytics, monitoring/alerts.
