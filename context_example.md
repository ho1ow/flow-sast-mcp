# Business Context — Example App

## System Overview
B2B e-commerce platform for wholesale orders. Customers are businesses with
custom pricing tiers. Order data contains commercially sensitive pricing info.

## Custom Sinks (security-critical methods)

### OrderRepository::rawExec
- Class: `App\Repositories\OrderRepository`
- Method: `rawExec(string $sql)`
- Risk: Executes raw SQL — SQLi if user input reaches this
- Vuln type: sqli

### PaymentGateway::charge
- Class: `App\Services\PaymentGateway`
- Method: `charge(array $data)`
- Risk: Customer-controlled amount field — business logic bypass
- Vuln type: business_critical

## Custom Sources (non-HTTP inputs)

### QueueConsumer::getPayload
- Class: `App\Queue\QueueConsumer`
- Method: `getPayload()`
- Source type: queue (SQS)
- Note: Payload originates from webhook → queue → worker, not direct HTTP

### EventListener::handle
- Class: `App\Listeners\EventListener`
- Method: `handle(Event $event)`
- Source type: event
- Note: Event data comes from external webhook callback

## Sensitive Flows

### /webhook/payment (POST)
- Risk: No authentication required, POST body is attacker-controlled
- Impact: If any sink processes this data, critical

### /checkout/guest (POST)
- Risk: Unauthenticated order creation
- Impact: Guest checkout allows order manipulation without auth

## Business Notes
- Multi-tenant: company_id must always be enforced on queries
- All financial writes must go through PaymentGateway (no direct DB writes)
- Admin panel at /admin/* uses separate auth middleware `AdminGuard`
- Pricing tier data is confidential B2B — IDOR here = business-critical
- Background workers process SQS queue from external payment providers
