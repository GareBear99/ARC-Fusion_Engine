"""Role ladder + PBKDF2 password primitives.

ARC-Core enforces a 5-rung role ladder (``observer < analyst < operator <
approver < admin``) and supports two orthogonal authentication mechanisms
for FastAPI route guards:

1. **Session-token auth** via ``Authorization: Bearer <token>`` — resolved
   through ``arc.services.authn.resolve_session``. Session role fully
   overrides the header-based ``X-ARC-Role`` + shared-token flow.
2. **Header auth** via ``X-ARC-Role`` + ``X-ARC-Token`` — intended for demo
   deployments and test clients. ``ARC_SHARED_TOKEN`` gates non-observer
   routes when configured, and also gates observer routes in non-demo mode.

Password hashing is PBKDF2-HMAC-SHA256 at 120 000 iterations with a 16-byte
random salt. See ``docs/ARCHITECTURE.md`` §6.
"""
from __future__ import annotations
from fastapi import Header, HTTPException
from arc.core.config import DEMO_MODE, SHARED_TOKEN

#: Role-name to rank mapping. Higher number == more privilege. Callers should
#: treat this as ordered — ``require_role`` compares ranks, not strings.
ROLE_ORDER = {"observer": 1, "analyst": 2, "operator": 3, "approver": 4, "admin": 5}


def require_role(required: str, x_arc_role: str = Header(default="observer"), x_arc_token: str | None = Header(default=None), authorization: str | None = Header(default=None)) -> str:
    """FastAPI dependency: enforce that the caller has at least ``required`` rank.

    Resolution order:

    1. If a ``Authorization: Bearer`` session token is present, trust it and
       use its role (401 on invalid/expired).
    2. Else use ``X-ARC-Role`` header (default ``observer``). Unknown role → 400.
    3. If caller's rank < required rank → 403.
    4. If ``ARC_SHARED_TOKEN`` is configured *and* the required role is above
       observer, ``X-ARC-Token`` must match or 401.
    5. In non-demo mode, step 4 also applies to observer calls.

    Returns the resolved role string on success.
    """
    session_role = None
    if authorization and authorization.startswith("Bearer "):
        from arc.services.authn import resolve_session
        session = resolve_session(authorization.replace("Bearer ", "", 1))
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        session_role = session["role"]
    role = (session_role or x_arc_role or "observer").lower()
    if role not in ROLE_ORDER:
        raise HTTPException(status_code=400, detail=f"Unknown role: {role}")
    if ROLE_ORDER[role] < ROLE_ORDER[required]:
        raise HTTPException(status_code=403, detail=f"{required} role required")
    if session_role:
        return role
    if SHARED_TOKEN and required != "observer" and x_arc_token != SHARED_TOKEN:
        raise HTTPException(status_code=401, detail="Valid X-ARC-Token required")
    if not DEMO_MODE and required == "observer" and role == "observer" and SHARED_TOKEN and x_arc_token != SHARED_TOKEN:
        raise HTTPException(status_code=401, detail="Valid X-ARC-Token required")
    return role


def make_password_hash(password: str, salt: str | None = None) -> tuple[str, str]:
    """Derive a PBKDF2-HMAC-SHA256 hash for ``password``.

    120 000 iterations, 16-byte random salt (unless a prior salt is supplied
    for verification). Returns ``(salt_b64, hash_b64)`` as base64-ASCII
    strings suitable for ``auth_users.password_salt`` / ``password_hash``.
    """
    import base64, hashlib, os
    raw_salt = salt.encode("utf-8") if salt else os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw_salt, 120_000)
    return base64.b64encode(raw_salt).decode("ascii"), base64.b64encode(derived).decode("ascii")


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    """Constant-time verify ``password`` against a stored ``(salt, hash)``.

    Uses ``hmac.compare_digest`` to avoid leaking timing information about
    partial hash matches.
    """
    import base64, hashlib, hmac
    salt = base64.b64decode(salt_b64.encode("ascii"))
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return hmac.compare_digest(base64.b64encode(candidate).decode("ascii"), hash_b64)
