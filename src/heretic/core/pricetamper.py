"""Deterministic price tampering (mechanical) — negative-quantity / client-value injection.

The clean, low-FP signal: submit a NEGATIVE quantity to a cart/order-item endpoint. No
legitimate app stores a negative quantity (it makes the order total negative), so if the
server accepts it and reflects it back, the "quantity must be positive / price is
server-side" invariant is broken — confirmed, deterministically. State-changing (it adds
a throwaway line item): live-gated.
"""
from __future__ import annotations

from typing import Any

from ..config import Config
from .models import Hypothesis

# endpoints that create/update order line items
_MARKERS = ["basketitem", "basket-item", "cartitem", "cart-item", "orderitem", "order-item",
            "lineitem", "line-item", "/basket", "/cart", "/orders", "/purchase", "/checkout"]
_BUILTIN = ["/api/BasketItems", "/api/CartItems", "/api/OrderItems", "/api/basket/items",
            "/api/cart/items", "/api/orderitems", "/rest/basket"]
# quantity-ish fields whose reflected NEGATIVE value proves the tamper
QTY_FIELDS = ["quantity", "qty", "count", "units", "numberofitems", "amount"]


def candidate_paths(cfg: Config, endpoints: list) -> list[str]:
    paths: set[str] = set(_BUILTIN)
    for ep in endpoints:
        path = ep.get("path") if isinstance(ep, dict) else ep
        low = (path or "").lower()
        if path and "{" not in path and any(m in low for m in _MARKERS):
            paths.add(path)
    return sorted(paths)


def build_pricetamper_hypotheses(cfg: Config, endpoints: list) -> list[Hypothesis]:
    return [Hypothesis(
        invariant_id="PRICE:negative_quantity",
        bug_class="price_tamper",
        description="a cart/order line item accepts a negative quantity (negative order total)",
        request_sequence=[],
        expected_safe="quantity must be a positive integer; totals are computed server-side",
        as_roles=["userA"],
        meta={"paths": candidate_paths(cfg, endpoints)},
    )]


def bodies(basket_id: Any, product_id: Any, qty: int = -100) -> list[dict]:
    """Common cart-item shapes carrying a negative quantity."""
    return [
        {"BasketId": basket_id, "ProductId": product_id, "quantity": qty},
        {"basketId": basket_id, "productId": product_id, "quantity": qty},
        {"cartId": basket_id, "productId": product_id, "qty": qty},
        {"ProductId": product_id, "quantity": qty},
        {"productId": product_id, "quantity": qty},
        {"quantity": qty},
    ]


def reflects_negative_quantity(obj: Any) -> tuple[str, Any] | None:
    """Find a quantity-ish field with a negative numeric value anywhere in the response."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in QTY_FIELDS and isinstance(v, (int, float)) and not isinstance(v, bool) and v < 0:
                return k, v
            hit = reflects_negative_quantity(v)
            if hit:
                return hit
    elif isinstance(obj, list):
        for x in obj:
            hit = reflects_negative_quantity(x)
            if hit:
                return hit
    return None
