"""Deterministic workflow bypass (mechanical) — finalize a workflow without its prerequisite.

Two crisp signals:

  1. Unpaid finalization — a checkout / place-order endpoint returns an order confirmation
     when the caller never went through a payment step. HERETIC controls that it never paid,
     so an order confirmation coming back = the payment prerequisite was skipped.
  2. Client-controlled state — an order/subscription create endpoint accepts and reflects a
     client-supplied workflow state (`status: "paid"`, `paid: true`, `delivered: true`), i.e.
     the client dictates a state the server should own.

State-changing (creates orders): live-gated.
"""
from __future__ import annotations

from typing import Any

from ..config import Config
from .models import Hypothesis

# checkout / order-finalization endpoints ({bid} is filled from the login response)
CHECKOUT_PATHS = [
    "/rest/basket/{bid}/checkout", "/api/basket/{bid}/checkout", "/rest/basket/{bid}/order",
    "/api/checkout", "/rest/checkout", "/api/orders/checkout", "/checkout", "/api/order/checkout",
    "/api/purchase", "/api/orders/place",
]
# response keys that specifically mean "an order was CONFIRMED/placed" (not a bare id echo,
# which many endpoints return and would false-positive)
ORDER_KEYS = {"orderconfirmation", "confirmationid", "ordernumber", "trackingid", "invoiceid"}
# order/subscription create endpoints whose reflected client state proves the bypass
CREATE_MARKERS = ["order", "subscription", "membership", "booking", "reservation", "invoice", "payment"]
# workflow-state (field, value) pairs to inject at create
STATE_FIELDS: list[tuple[str, Any]] = [
    ("status", "completed"), ("status", "paid"), ("status", "delivered"), ("status", "shipped"),
    ("paid", True), ("isPaid", True), ("completed", True), ("delivered", True),
    ("orderStatus", "delivered"), ("paymentStatus", "paid"), ("state", "approved"),
]


def order_create_paths(cfg: Config, endpoints: list) -> list[str]:
    paths: set[str] = set()
    for ep in endpoints:
        path = ep.get("path") if isinstance(ep, dict) else ep
        low = (path or "").lower()
        if path and "{" not in path and any(m in low for m in CREATE_MARKERS):
            paths.add(path)
    return sorted(paths)


def build_workflow_hypotheses(cfg: Config, endpoints: list) -> list[Hypothesis]:
    return [Hypothesis(
        invariant_id="WORKFLOW:finalize_without_prereq",
        bug_class="workflow_bypass",
        description="an order can be finalized without its payment/state prerequisite",
        request_sequence=[],
        expected_safe="finalization requires a completed payment; workflow state is server-owned",
        as_roles=["userA"],
        meta={"checkout_paths": list(CHECKOUT_PATHS), "create_paths": order_create_paths(cfg, endpoints)},
    )]


def order_confirmation(obj: Any) -> tuple[str, Any] | None:
    """Find an order-confirmation-like key with a truthy value in the response."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in ORDER_KEYS and v:
                return k, v
            hit = order_confirmation(v)
            if hit:
                return hit
    elif isinstance(obj, list):
        for x in obj:
            hit = order_confirmation(x)
            if hit:
                return hit
    return None


def reflects_state(obj: Any, field: str, value: Any) -> bool:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() == field.lower():
                if isinstance(value, bool) and (v is True or str(v).lower() == "true"):
                    return True
                if str(v).lower() == str(value).lower():
                    return True
            if reflects_state(v, field, value):
                return True
    elif isinstance(obj, list):
        return any(reflects_state(x, field, value) for x in obj)
    return False
