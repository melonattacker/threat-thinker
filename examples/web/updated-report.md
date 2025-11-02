# Threat Analysis Report

## Threat Summary

| ID | Threat | Severity | Score |
|----|---------|---------|-------|
| T001 | Unencrypted Internal API Communication Exposes PII | High | 8.0 |
| T002 | Unknown Protocols on Sensitive Internal Connections | High | 8.0 |
| T003 | Cache Service Lacks Authentication Controls | High | 7.0 |
| T004 | No Evidence of Secrets Management for Credentials in App and DB | High | 7.0 |
| T005 | Sensitive Data in Database May Be Unencrypted at Rest | High | 7.0 |

## Threat Details

### T001: Unencrypted Internal API Communication Exposes PII

**Severity:** High

**Score:** 8.0

**STRIDE:** Information Disclosure, Tampering

**Affected Components:** api, app

**Why:** API communicates with app over HTTP (not HTTPS), risking PII exposure and tampering in transit.

**References:** ASVS V9.1.1, ASVS V10.2.1, CWE-319

**Recommended Actions:**

Enforce TLS 1.2+ for all internal service-to-service communications, especially where PII is present.

---

### T002: Unknown Protocols on Sensitive Internal Connections

**Severity:** High

**Score:** 8.0

**STRIDE:** Information Disclosure, Tampering

**Affected Components:** api, cache, app, logs, logs, analytics, app, monitor, monitor, alerts

**Why:** Several internal edges use 'unknown' protocols, risking unencrypted or unauthenticated data transfer.

**References:** ASVS V9.1.1, ASVS V10.2.1, CWE-319

**Recommended Actions:**

Explicitly specify and enforce secure protocols (e.g., HTTPS, TLS) for all internal service connections.

---

### T003: Cache Service Lacks Authentication Controls

**Severity:** High

**Score:** 7.0

**STRIDE:** Elevation of Privilege, Information Disclosure

**Affected Components:** cache

**Why:** Cache node has null 'auth', risking unauthorized access to internal data.

**References:** ASVS V2.1.1, ASVS V4.1.1, CWE-284

**Recommended Actions:**

Implement strong authentication and access controls for the cache service.

---

### T004: No Evidence of Secrets Management for Credentials in App and DB

**Severity:** High

**Score:** 7.0

**STRIDE:** Information Disclosure, Elevation of Privilege

**Affected Components:** app, db

**Why:** App and DB nodes store credentials and secrets, but no evidence of secure secrets management.

**References:** ASVS V10.3.1, ASVS V10.3.2, CWE-798

**Recommended Actions:**

Use a centralized secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager) for all credentials.

---

### T005: Sensitive Data in Database May Be Unencrypted at Rest

**Severity:** High

**Score:** 7.0

**STRIDE:** Information Disclosure

**Affected Components:** db

**Why:** Database node stores PII, secrets, and credentials, but no evidence of encryption at rest.

**References:** ASVS V10.1.1, ASVS V10.2.1, CWE-311

**Recommended Actions:**

Enable strong encryption at rest for all sensitive data in the database.

---

