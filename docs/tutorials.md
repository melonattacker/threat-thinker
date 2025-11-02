# Tutorials
## Tutorial 1: Analyze simple web application
In this example, we will analyze the architecture diagram of a simple web application.  written in mermaid and identify potential threats.

### What This Does
- Analyzes a simple 3-tier web application architecture with User → API Gateway → App Service → Database flow
- Uses Mermaid diagram format to parse the system components and data flows
- Automatically infers potential security hints and generates the top 5 highest-priority threats
- Applies STRIDE methodology to identify threats across spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege
- Outputs results in Markdown format with detailed threat descriptions, affected components, and security references

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
    --format md \
    --out reports/web-report.md
```

### Discovered potential threats

| ID | Severity | Title | Why | Affected | STRIDE | References | Evidence | Score |
|---|---|---|---|---|---|---|---|---|
| T001 | High | API lacks authentication, allowing spoofing from Internet | API in DMZ has no authentication, so anyone on the Internet can impersonate users or services. | User, api | Spoofing, Elevation of Privilege | ASVS V2.1 - Authentication Architecture, CWE-287 | user, api | 8 |
| T002 | High | Unencrypted HTTP between API and App exposes sensitive data | HTTP (not HTTPS) between DMZ API and Private App risks data interception or manipulation. | api, app | Information Disclosure, Tampering | ASVS V9.1 - Communications Security, CWE-319 | api, app, api->app | 7 |
| T003 | Medium | API is exposed to Internet, increasing DoS risk | API in DMZ is directly reachable from Internet, making it a target for DoS attacks. | api | Denial of Service | ASVS V10.2 - Denial of Service, CWE-400 | user, api | 6 |
| T004 | Medium | Internal data may be exposed via API due to lack of access controls | API may expose sensitive internal DB data to Internet users if access controls are missing. | api, db | Information Disclosure | ASVS V4.2 - Access Control, CWE-200 | api, db | 6 |
| T005 | Medium | Lack of audit/logging enables repudiation | No evidence of logging or audit trails, making it hard to trace malicious or unauthorized actions. | api, app | Repudiation | ASVS V8.1 - Logging and Monitoring, CWE-778 | api, app, api->app | 5 |

### What Was Discovered
The analysis identified 5 critical security threats in this simple web application:

**High Severity Threats:**
- **Missing API Authentication**: The API Gateway lacks authentication mechanisms, allowing anyone to impersonate legitimate users or services
- **Unencrypted Internal Communication**: HTTP is used between the API and App Service, exposing sensitive data to interception

**Medium Severity Threats:**  
- **DoS Vulnerability**: The Internet-facing API is susceptible to denial of service attacks
- **Insufficient Access Controls**: The API may expose sensitive database information due to missing access controls
- **No Audit Logging**: Lack of logging capabilities makes it difficult to detect and investigate security incidents

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
    --format md \
    --out reports/aws-report.md
```

### Discovered potential threats

| ID | Severity | Title | Why | Affected | STRIDE | References | Evidence | Score |
|---|---|---|---|---|---|---|---|---|
| T001 | High | PII Exposure in Database Communication | PII is transmitted over TCP with unspecified encryption, risking data leakage or modification in transit. | ECS Service (Fargate), Aurora (RDS) | Information Disclosure, Tampering | ASVS V9.1.1, ASVS V10.2.1, CWE-319 | ecs_service_fargate, aurora_rds, ecs_service_fargate->aurora_rds | 8 |
| T002 | High | Unencrypted Traffic Between Load Balancer and ECS Service | HTTP (not HTTPS) is used between the load balancer and ECS, risking PII/internal data exposure or tampering. | Application Load Balancer, ECS Service (Fargate) | Information Disclosure, Tampering | ASVS V9.1.1, ASVS V10.2.1, CWE-319 | application_load_balancer, ecs_service_fargate, application_load_balancer->ecs_service_fargate | 8 |
| T003 | High | Potential Lack of End-to-End Authentication | No authentication is specified between the load balancer and ECS, risking unauthorized access to internal services. | Application Load Balancer, ECS Service (Fargate) | Spoofing, Elevation of Privilege | ASVS V2.1.1, ASVS V2.2.2, CWE-287 | application_load_balancer, ecs_service_fargate, application_load_balancer->ecs_service_fargate | 7 |
| T004 | Medium | Credential Exposure from User to CloudFront | User credentials are transmitted; if HTTPS is misconfigured, credentials could be intercepted or replayed. | User, CloudFront | Information Disclosure, Spoofing | ASVS V2.1.1, ASVS V9.1.1, CWE-522 | user, cloudfront, user->cloudfront | 6 |
| T005 | Medium | Insufficient Access Controls on S3 Bucket (Assets) | Internal data in S3 may be accessible if bucket policies are overly permissive or misconfigured. | ECS Service (Fargate), S3 Bucket (assets) | Information Disclosure, Elevation of Privilege | ASVS V4.1.3, ASVS V1.4.3, CWE-284 | ecs_service_fargate, s3_bucket_assets, ecs_service_fargate->s3_bucket_assets | 6 |
| T006 | Medium | Denial of Service via Unrestricted Queue/Event Injection | If access controls are weak, attackers could flood queues or events, exhausting Lambda or backend resources. | SQS Queue (jobs), SNS Topic (events), Lambda Worker | Denial of Service | ASVS V7.5.1, ASVS V10.4.3, CWE-400 | sqs_queue_jobs, sns_topic_events, lambda_worker, sqs_queue_jobs->lambda_worker, sns_topic_events->lambda_worker | 5 |
| T007 | Medium | Lack of Message Integrity in SQS/SNS Communications | No evidence of message signing or integrity checks, risking message tampering or spoofing in internal queues. | ECS Service (Fargate), SQS Queue (jobs), SNS Topic (events), Lambda Worker | Tampering, Repudiation | ASVS V10.4.1, ASVS V10.4.2, CWE-345 | ecs_service_fargate, sqs_queue_jobs, sns_topic_events, lambda_worker, ecs_service_fargate->sqs_queue_jobs, sns_topic_events->lambda_worker | 5 |
| T008 | Medium | Potential Over-Privileged Lambda Worker | Lambda may have excessive permissions to SQS/SNS or other AWS resources, increasing lateral movement risk. | Lambda Worker | Elevation of Privilege, Tampering | ASVS V1.4.2, ASVS V4.2.1, CWE-250 | lambda_worker, sqs_queue_jobs->lambda_worker, sns_topic_events->lambda_worker | 5 |
| T009 | Medium | Insufficient Audit Logging for Sensitive Operations | No evidence of audit logging for access to PII or internal data, hindering incident response and accountability. | ECS Service (Fargate), Aurora (RDS), S3 Bucket (assets) | Repudiation | ASVS V10.1.1, ASVS V10.2.1, CWE-778 | ecs_service_fargate, aurora_rds, s3_bucket_assets, ecs_service_fargate->aurora_rds, ecs_service_fargate->s3_bucket_assets | 4 |
| T010 | Medium | Potential Data Leakage via Misconfigured CloudFront | CloudFront may expose sensitive headers or cache private data if not properly configured. | CloudFront | Information Disclosure | ASVS V9.1.1, ASVS V14.4.1, CWE-200 | cloudfront, user->cloudfront, cloudfront->application_load_balancer | 4 |

### What Was Discovered
The AWS architecture analysis revealed 10 significant security threats, highlighting the complexity of cloud security:

**High Severity Threats:**
- **PII Exposure in Database Communications**: Sensitive personal data transmitted between ECS and Aurora without proper encryption
- **Unencrypted Load Balancer Traffic**: HTTP used between ALB and ECS services, risking data interception
- **Missing Internal Authentication**: No authentication specified between load balancer and ECS services

**Medium Severity Threats Include:**
- **Credential Exposure**: User credentials potentially vulnerable during CloudFront transmission
- **S3 Access Control Issues**: Asset bucket may have overly permissive access policies
- **Message Queue Vulnerabilities**: SQS/SNS communications lack integrity verification
- **Over-privileged Lambda Functions**: Workers may have excessive AWS permissions
- **Insufficient Logging**: Limited audit trails for sensitive operations
- **CloudFront Misconfigurations**: Potential for exposing sensitive headers or caching private data