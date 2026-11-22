#!/usr/bin/env python3
"""a2a_auth.py — agent-to-agent authenticated task-execution protocol.

Reference implementation (Python standard library only) of the design in
docs/auth-design.md. LAB ONLY: all keys are freshly generated test keys;
no live credentials, no live accounts, no transactions.

Primitives
----------
* Agent identity: Ed25519 keypair (scripts/ed25519.py, RFC 8032).
  agent_id = "agent-" + first 16 hex chars of SHA-256(public key).
* Capability token: a per-task scoped credential. JSON envelope signed
  by the issuer key. Binds agent_id, task_id, capability list, validity
  window, and a 128-bit nonce. Verification checks the issuer signature
  against the verifier's TRUSTED issuer key (never the key named inside
  the token), expiry, task binding, and capability containment.
* Signed task action: canonical JSON envelope signed by the agent key.
  Binds agent_id, task_id, action, capability, nonce, issued_at, and
  the SHA-256 of the submitted payload. Verification checks the agent
  signature, the capability token, the nonce (single-use), the
  clock-skew window, the payload hash, and the revocation list.

Security properties enforced by verify_action (all measured in the
lab drill, scripts/drill.py):
  signature validity, key/identity binding, capability containment,
  task binding, expiry, single-use nonces, clock-skew window,
  payload integrity, revocation, payload size cap.
"""
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scripts"))

from ed25519 import public_key, sign, verify

# --- design parameters (see configs/auth-parameters.json) ---------------
CLOCK_SKEW_SECONDS = 300          # allowed |now - issued_at|
MAX_PAYLOAD_BYTES = 1 * 1024 * 1024   # 1 MiB evidence payload cap
NONCE_BYTES = 16                  # 128-bit nonce
TOKEN_TTL_SECONDS = 3600          # capability token lifetime (1 h)
ACTION_TTL_SECONDS = 900          # signed action validity (15 min)

# Actions in the task lifecycle, and the capability each one needs.
ACTIONS = {
    "request": "request",
    "accept": "accept",
    "submit_evidence": "submit_evidence",
    "respond_verification": "respond_verification",
    "request_reward": "request_reward",
}


def agent_id_for(public_key_bytes: bytes) -> str:
    """Stable agent identifier derived from the public key."""
    return "agent-" + hashlib.sha256(public_key_bytes).hexdigest()[:16]


def new_agent_keypair():
    """Generate a fresh LAB Ed25519 agent keypair. Returns (sk, pk)."""
    sk = os.urandom(32)
    pk = public_key(sk)
    return sk, pk


def canonical_json(obj) -> bytes:
    """Canonical JSON encoding: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Capability tokens (issued by the platform issuer key)
# --------------------------------------------------------------------------

def issue_capability_token(issuer_sk: bytes, issuer_pk: bytes,
                           agent_pk: bytes, task_id: str,
                           capabilities, issued_at: int,
                           ttl_seconds: int = TOKEN_TTL_SECONDS,
                           nonce: bytes = None) -> dict:
    """Issue a per-task scoped capability token, signed by the issuer."""
    nonce = nonce if nonce is not None else os.urandom(NONCE_BYTES)
    body = {
        "version": 1,
        "kind": "capability-token",
        "agent_id": agent_id_for(agent_pk),
        "agent_pk": agent_pk.hex(),
        "task_id": task_id,
        "capabilities": sorted(set(capabilities)),
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_seconds,
        "nonce": nonce.hex(),
        "issuer_pk": issuer_pk.hex(),
    }
    body["signature"] = sign(canonical_json(body), issuer_sk,
                             issuer_pk).hex()
    return body


def verify_capability_token(token: dict, now: int, task_id: str,
                           action: str, trusted_issuer_pk: bytes = None):
    """Verify a capability token for a given task and action.

    The issuer public key must come from the verifier's trusted set,
    never from inside the token itself: a token that names its own
    issuer would let any key self-issue capabilities. When
    trusted_issuer_pk is given, the token's issuer_pk must equal it.
    Returns (ok, reason). Reasons are stable strings used by the drill.
    """
    required = {"version", "kind", "agent_id", "agent_pk", "task_id",
                "capabilities", "issued_at", "expires_at", "nonce",
                "issuer_pk", "signature"}
    if not required.issubset(token.keys()):
        return False, "malformed-token"
    if token["kind"] != "capability-token" or token["version"] != 1:
        return False, "malformed-token"
    if trusted_issuer_pk is not None:
        if token["issuer_pk"] != trusted_issuer_pk.hex():
            return False, "untrusted-issuer"
    body = {k: v for k, v in token.items() if k != "signature"}
    issuer_pk = bytes.fromhex(token["issuer_pk"])
    if not verify(bytes.fromhex(token["signature"]),
                  canonical_json(body), issuer_pk):
        return False, "bad-issuer-signature"
    if token["task_id"] != task_id:
        return False, "task-mismatch"
    if ACTIONS.get(action, action) not in token["capabilities"]:
        return False, "scope-denied"
    if now > token["expires_at"]:
        return False, "token-expired"
    if now < token["issued_at"] - CLOCK_SKEW_SECONDS:
        return False, "token-not-yet-valid"
    return True, "ok"


# --------------------------------------------------------------------------
# Signed task actions
# --------------------------------------------------------------------------

def sign_task_action(agent_sk: bytes, agent_pk: bytes, task_id: str,
                     action: str, payload: bytes, issued_at: int,
                     nonce: bytes = None) -> dict:
    """Sign a task action. Returns the signed action envelope."""
    nonce = nonce if nonce is not None else os.urandom(NONCE_BYTES)
    body = {
        "version": 1,
        "kind": "task-action",
        "agent_id": agent_id_for(agent_pk),
        "agent_pk": agent_pk.hex(),
        "task_id": task_id,
        "action": action,
        "nonce": nonce.hex(),
        "issued_at": issued_at,
        "payload_sha256": sha256_hex(payload),
        "payload_bytes": len(payload),
    }
    body["signature"] = sign(canonical_json(body), agent_sk,
                             agent_pk).hex()
    return body


class Verifier:
    """Stateful verifier: replay cache + revocation list.

    The replay cache holds seen nonces until the action validity window
    has passed; the revocation list holds revoked agent ids and token
    nonces. Both are in-memory in this reference implementation; a
    production deployment would persist them (see docs/auth-design.md).
    """

    def __init__(self, issuer_pk: bytes):
        self.issuer_pk = issuer_pk
        self._seen_nonces = {}          # nonce hex -> expiry unix time
        self._revoked_agents = set()    # agent_id strings
        self._revoked_tokens = set()    # token nonce hex strings

    def revoke_agent(self, agent_id: str):
        self._revoked_agents.add(agent_id)

    def revoke_token(self, token_nonce_hex: str):
        self._revoked_tokens.add(token_nonce_hex)

    def _prune(self, now: int):
        expired = [n for n, exp in self._seen_nonces.items() if exp < now]
        for n in expired:
            del self._seen_nonces[n]

    def verify_action(self, action_envelope: dict, token: dict,
                      payload: bytes, now: int):
        """Verify one signed task action against its capability token.

        Returns (ok, reason). Reasons are stable strings used by the drill.
        """
        self._prune(now)
        required = {"version", "kind", "agent_id", "agent_pk", "task_id",
                    "action", "nonce", "issued_at", "payload_sha256",
                    "payload_bytes", "signature"}
        if not required.issubset(action_envelope.keys()):
            return False, "malformed-action"
        if (action_envelope["kind"] != "task-action"
                or action_envelope["version"] != 1):
            return False, "malformed-action"

        agent_pk = bytes.fromhex(action_envelope["agent_pk"])
        if agent_id_for(agent_pk) != action_envelope["agent_id"]:
            return False, "identity-mismatch"

        # 1. Agent signature over the canonical envelope.
        body = {k: v for k, v in action_envelope.items() if k != "signature"}
        if not verify(bytes.fromhex(action_envelope["signature"]),
                      canonical_json(body), agent_pk):
            return False, "bad-agent-signature"

        # 2. Payload integrity and size cap.
        if len(payload) > MAX_PAYLOAD_BYTES:
            return False, "payload-too-large"
        if len(payload) != action_envelope["payload_bytes"]:
            return False, "payload-size-mismatch"
        if sha256_hex(payload) != action_envelope["payload_sha256"]:
            return False, "payload-mismatch"

        # 3. Freshness window.
        if now > action_envelope["issued_at"] + ACTION_TTL_SECONDS:
            return False, "action-expired"
        if now < action_envelope["issued_at"] - CLOCK_SKEW_SECONDS:
            return False, "action-not-yet-valid"

        # 4. Single-use nonce (replay protection).
        if action_envelope["nonce"] in self._seen_nonces:
            return False, "replay-nonce"

        # 5. Revocation.
        if action_envelope["agent_id"] in self._revoked_agents:
            return False, "agent-revoked"
        if token.get("nonce") in self._revoked_tokens:
            return False, "token-revoked"

        # 6. Capability token: issuer signature (against the verifier's
        #    trusted issuer key), task binding, scope, expiry.
        ok, reason = verify_capability_token(
            token, now, action_envelope["task_id"],
            action_envelope["action"], trusted_issuer_pk=self.issuer_pk)
        if not ok:
            return False, reason
        if token.get("agent_id") != action_envelope["agent_id"]:
            return False, "token-agent-mismatch"

        # Accept: record the nonce so it can never be reused.
        self._seen_nonces[action_envelope["nonce"]] = (
            action_envelope["issued_at"] + ACTION_TTL_SECONDS)
        return True, "ok"


if __name__ == "__main__":
    # Smoke check: issue a token, sign an action, verify it.
    now = int(time.time())
    issuer_sk, issuer_pk = new_agent_keypair()
    agent_sk, agent_pk = new_agent_keypair()
    token = issue_capability_token(issuer_sk, issuer_pk, agent_pk,
                                   "task-lab-001", ["accept"], now)
    action = sign_task_action(agent_sk, agent_pk, "task-lab-001",
                              "accept", b"accepting", now)
    v = Verifier(issuer_pk)
    print(v.verify_action(action, token, b"accepting", now))
    print(v.verify_action(action, token, b"accepting", now))
