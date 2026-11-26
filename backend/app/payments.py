"""Razorpay subscription checkout and webhook helpers for DataLineage AI."""
from __future__ import annotations

import httpx
from .config import settings

# Monthly list prices. Values are major currency units; Razorpay expects the
# smallest currency unit in the Plan API (all launch currencies below use 2).
PRICING = {
    "INR": {"symbol": "₹", "country": "India", "starter": 1999, "professional": 7999, "business": 19999},
    "USD": {"symbol": "$", "country": "United States", "starter": 29, "professional": 99, "business": 249},
    "GBP": {"symbol": "£", "country": "United Kingdom", "starter": 25, "professional": 79, "business": 199},
    "EUR": {"symbol": "€", "country": "Euro area", "starter": 29, "professional": 89, "business": 229},
    "SGD": {"symbol": "S$", "country": "Singapore", "starter": 39, "professional": 129, "business": 299},
    "AED": {"symbol": "AED ", "country": "United Arab Emirates", "starter": 109, "professional": 369, "business": 899},
    "AUD": {"symbol": "A$", "country": "Australia", "starter": 45, "professional": 149, "business": 379},
}
PLAN_NAMES = {"starter": "Starter", "professional": "Professional", "business": "Business"}


class PaymentConfigurationError(RuntimeError):
    pass


def _credentials() -> tuple[str, str]:
    key_id = settings.razorpay_key_id
    key_secret = settings.razorpay_key_secret
    if not key_id or not key_secret:
        raise PaymentConfigurationError("Razorpay is not configured. Add the test or live API keys to backend/.env")
    return key_id, key_secret


def razorpay_request(method: str, path: str, payload: dict | None = None) -> dict:
    key_id, key_secret = _credentials()
    try:
        response = httpx.request(
            method,
            f"https://api.razorpay.com/v1/{path.lstrip('/')}",
            json=payload,
            auth=(key_id, key_secret),
            timeout=25.0,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        # Never return provider response bodies: they can contain customer data.
        raise RuntimeError(f"Razorpay API returned HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError("Could not connect to Razorpay. Check network connectivity and try again.") from exc


def create_subscription(*, org_id: str, plan: str, currency: str, customer_email: str) -> dict:
    if plan not in PLAN_NAMES:
        raise ValueError("Choose Starter, Professional or Business")
    currency = currency.upper()
    if currency not in PRICING:
        raise ValueError("Unsupported billing currency")
    price = PRICING[currency][plan]
    plan_data = razorpay_request("POST", "plans", {
        "period": "monthly",
        "interval": 1,
        "item": {
            "name": f"DataLineage AI {PLAN_NAMES[plan]} Monthly",
            "amount": int(price * 100),
            "currency": currency,
            "description": f"DataLineage AI {PLAN_NAMES[plan]} subscription",
        },
        "notes": {"product": "DataLineage AI", "tier": plan, "currency": currency},
    })
    subscription = razorpay_request("POST", "subscriptions", {
        "plan_id": plan_data["id"],
        "total_count": 120,
        "quantity": 1,
        "customer_notify": True,
        "notes": {
            "organization_id": org_id,
            "plan": plan,
            "currency": currency,
            "customer_email": customer_email[:254],
        },
    })
    return {
        "provider": "razorpay",
        "subscription_id": subscription["id"],
        "short_url": subscription.get("short_url"),
        "status": subscription.get("status", "created"),
        "plan_id": plan_data["id"],
        "plan": plan,
        "currency": currency,
        "amount": price,
    }
