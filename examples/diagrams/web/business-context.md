# Business Context: Example Web Application

## Scope
This context describes the web application represented by `system.mmd`: public users call an API Gateway, the API Gateway forwards requests to an App Service, and the App Service reads from and writes to the Customer DB.

The threat model should cover the user-facing API path, service-to-service communication, and database access performed by the App Service. It should not cover internal corporate IT systems, developer workstations, or third-party SaaS tools that are not shown in the diagram.

## Actors
- Public users submit account and profile requests through the API Gateway.
- Application operators review service health and security events.
- App Service instances access the Customer DB using service credentials.

## Sensitive Assets
- Customer identifiers, contact details, and profile attributes stored in the Customer DB.
- Session or access tokens presented to the API Gateway.
- Service credentials used by the App Service to connect to the Customer DB.
- Audit records for login, profile update, and administrative workflows.

## Assumptions and Requirements
- The API Gateway is internet-facing and must authenticate requests before forwarding protected operations.
- App Service to Customer DB traffic is expected to stay private and encrypted.
- Customer data should be protected from unauthorized read, update, and deletion.
- Availability of the API path is business-critical during business hours.
- Security-relevant events should be logged with enough detail to support investigation without exposing secrets or sensitive customer data.
