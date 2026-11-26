# Milestone 23 — Razorpay setup

## Pricing (monthly, proposed launch list prices)

| Market | Currency | Starter | Professional | Business |
|---|---:|---:|---:|---:|
| India | INR | 1,999 | 7,999 | 19,999 |
| United States | USD | 29 | 99 | 249 |
| United Kingdom | GBP | 25 | 79 | 199 |
| Euro area | EUR | 29 | 89 | 229 |
| Singapore | SGD | 39 | 129 | 299 |
| United Arab Emirates | AED | 109 | 369 | 899 |
| Australia | AUD | 45 | 149 | 379 |

These are proposed prices, not exchange-rate conversions or market-validated benchmarks. Enterprise is custom. Taxes and provider fees may apply.

## Configure test mode

1. Create/activate a Razorpay merchant account and complete required KYC and product approvals.
2. In Razorpay Dashboard, switch to Test Mode and generate API Key ID and Key Secret.
3. Add to `backend/.env`:

```dotenv
DATALINEAGE_RAZORPAY_MODE=test
DATALINEAGE_RAZORPAY_KEY_ID=rzp_test_...
DATALINEAGE_RAZORPAY_KEY_SECRET=...
DATALINEAGE_RAZORPAY_WEBHOOK_SECRET=...
```

4. Configure a Razorpay webhook URL pointing to `https://YOUR_PUBLIC_DOMAIN/webhooks/razorpay` and subscribe to at least `subscription.activated`, `subscription.charged`, `subscription.halted`, `subscription.cancelled`, and `subscription.completed`.
5. Copy the webhook secret into `DATALINEAGE_RAZORPAY_WEBHOOK_SECRET` and restart the backend.
6. Sign in as the workspace owner, select **Plans & Billing**, choose a currency and plan, and complete a test checkout.
7. Confirm the subscription changes from Free only after Razorpay sends a valid signed webhook.

## API behavior

- `GET /api/v1/billing/catalog` returns the published monthly price catalog.
- `POST /api/v1/organizations/{org_id}/billing/checkout` creates a Razorpay plan and subscription. Only the workspace owner can start checkout.
- `POST /webhooks/razorpay` verifies `X-Razorpay-Signature` against the raw request body and processes events idempotently.

The app never accepts a browser claim as proof of payment. It does not store card data. API keys and webhook secrets belong only in `backend/.env` or the production secret manager.

## Important international-payment notes

Razorpay documents international subscription support in supported currencies, with international subscription payments card-based and settlement to the merchant in INR. International payments and recurring payments must be enabled/approved on the merchant account. Availability can vary by merchant, customer country, payment method and regulatory requirements. Verify eligibility with Razorpay before advertising worldwide recurring checkout.

## Current implementation scope

This milestone includes monthly subscription checkout, owner authorization, webhook signature verification, event idempotency, and local subscription activation/status updates. It does not yet include self-service cancellation, proration, annual billing, refunds, tax calculation/invoicing, or a production reconciliation dashboard. Do not switch to live keys until test-mode checkout and webhook tests pass.
