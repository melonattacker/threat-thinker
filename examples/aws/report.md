# Threat Thinker Report

Generated: 2025-10-26T12:01:30.550794Z
Import Success: 100.0% (edges 6/6, labels 2/2)

| Severity | Title | Why | Affected | STRIDE | References | Evidence | Score |
|---|---|---|---|---|---|---|---|
| High | User Credential Exposure | If user credentials are compromised, attackers can impersonate legitimate users and access services. | User, Elastic Container Service | Spoofing, Information Disclosure | ASVS V5.1.3 | user, ecs | 9 |
| High | Unencrypted Database Connection | Using unencrypted TCP for database connections can expose sensitive data and allow tampering. | Elastic Container Service, Relational Database Service | Tampering, Information Disclosure | ASVS V5.1.2 | ecs, rds, ecs->rds | 8 |
| High | Insecure Transport Layer Security | If TLS is misconfigured or absent, data can be intercepted or altered during transmission. | CloudFront, Application Load Balancer | Tampering, Information Disclosure | ASVS V5.1.1 | cf, alb, cf->alb | 7 |
| High | Insufficient Authentication for S3 Access | If S3 bucket policies are misconfigured, unauthorized users may gain access to sensitive data. | Simple Storage Service | Elevation of Privilege, Information Disclosure | ASVS V5.2.1 | s3 | 7 |
| Medium | Insecure Internal Communication | Using HTTP for internal communication can expose sensitive data to internal threats. | Application Load Balancer, Elastic Container Service | Tampering, Information Disclosure | ASVS V5.1.2 | alb, ecs, alb->ecs | 6 |
| Medium | Unrestricted Access to SQS and Lambda | If access controls are not properly configured, unauthorized users may invoke Lambda functions or read SQS messages. | Simple Queue Service, AWS Lambda | Elevation of Privilege, Information Disclosure | ASVS V5.2.2 | sqs, lambda, sqs->lambda | 5 |
| Medium | Unsecured SNS Topic | If SNS topics are not secured, unauthorized users can publish or subscribe to sensitive notifications. | SNS Topic | Elevation of Privilege, Information Disclosure | ASVS V5.2.1 | sns | 5 |