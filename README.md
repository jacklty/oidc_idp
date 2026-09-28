# oidc_idp — forge a JWT, get real STS to verify it, land session tags

A minimal self-hosted OIDC identity provider for learning the
`sts:AssumeRoleWithWebIdentity` exchange. You own the signing key, so you can
mint JWTs with **arbitrary claims** — including AWS's session-tag claim — and
have real AWS STS verify and honor them.

## Files

| File | Purpose |
|---|---|
| `gen_keys.sh` | generate RSA-2048 signing keypair into `keys/` (gitignored) |
| `jwt.py` | RS256 sign/verify (openssl-backed) + PEM→JWK conversion and key thumbprints |
| `idp.py` | OIDC server: discovery, JWKS, guarded `/token` endpoint |
| `mint.py` | CLI to forge a JWT with custom claims and session tags |
| `exchange.sh` | mint → `aws sts assume-role-with-web-identity` |
| `tunnel.sh` | start `idp.py` behind a Cloudflare quick tunnel, auto-set `issuer` |
| `keys/` | `private.pem` (sign) + `public.pem` (served as JWKS) |

The JWKS `kid` and JWT header `kid` are derived from `keys/public.pem` using its
RFC 7638 JWK thumbprint. The JWT is signed with the matching `keys/private.pem`,
so the two files must remain a keypair. The `kid` remains stable until the key
pair changes.

## Quick start (offline)

```bash
./gen_keys.sh
./mint.py --sub alice --tag Team=eng --tag tenant=yellow --transitive Team --print-payload
#   prints a signed JWT; payload goes to stderr

# spin up the IdP
python3 idp.py --port 8765 --secret labsecret
curl -s http://localhost:8765/.well-known/openid-configuration | jq
curl -s http://localhost:8765/.well-known/jwks.json | jq '.keys[0]'

# mint via the server (any claims you like)
curl -s -X POST http://localhost:8765/token \
  -H "Authorization: Bearer labsecret" -H "Content-Type: application/json" \
  -d '{"sub":"svc","https://aws.amazon.com/tags":{"principal_tags":{"tenant":"yellow"}}}'
```

## The real-AWS exchange (once tunneled)

```bash
ROLE_ARN=arn:aws:iam::346992621599:role/oidc-lab \
ISS=https://<your-tunnel-host> \
./exchange.sh --tag Team=eng --tag tenant=yellow --transitive Team,tenant
```

Requirements (see below): a publicly reachable HTTPS hostname (Cloudflare
Tunnel), an IAM OIDC provider pointing at it, a role trusting that provider.

## How the session-tag claim works

AWS maps claims under the `https://aws.amazon.com/tags` namespace to session
tags, which appear as `aws:PrincipalTag/<key>` on the assumed role session.

Nested format (used by `mint.py`):

```json
{
  "https://aws.amazon.com/tags": {
    "principal_tags": { "Team": "eng", "tenant": "yellow" },
    "transitive_tag_keys": ["Team"]
  }
}
```

Flattened format (for IdPs that can't do nested objects, e.g. Entra ID):

```json
{
  "https://aws.amazon.com/tags/principal_tags/Team": "eng",
  "https://aws.amazon.com/tags/transitive_tag_keys": ["Team"]
}
```

Rules:
- Tag values must be single strings; up to **50** tags.
- `transitive_tag_keys` tags survive role chaining.
- A session tag with the same key as a role tag **overrides** it.
- The role's trust policy must allow `sts:TagSession` alongside
  `sts:AssumeRoleWithWebIdentity` for tagged sessions.
- **The credentials JSON does not show the tags.** With a no-permissions role,
  observe them in CloudTrail (`AssumeRoleWithWebIdentity` event), or attach an
  ABAC policy using `aws:PrincipalTag/<key>` and watch allow vs deny.

## Trust-policy shape for the lab role

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::346992621599:oidc-provider/<host>" },
    "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
    "Condition": {
      "StringEquals": { "<host>:aud": "sts.amazonaws.com" }
    }
  }]
}
```

## Cloudflare Tunnel — run the IdP behind Cloudflare

Quickest path (no domain needed; `cloudflared` must be installed):

```bash
./tunnel.sh                 # starts idp.py + a quick tunnel, prints issuer/jwks_uri
# in another shell, mint + exchange:
ISS=https://<printed-host> ROLE_ARN=arn:aws:iam::346992621599:role/oidc-lab \
  ./exchange.sh --tag Team=eng --tag tenant=yellow --transitive Team,tenant
```

What it does:
- Starts `cloudflared tunnel --url http://localhost:8765` (outbound-only HTTPS,
  so it works from a private-subnet instance with **no public IP** — e.g. the
  `qa-interactive-host` bastion in account 346992621599).
- Waits for the `*.trycloudflare.com` hostname, then starts `idp.py` with
  `--issuer https://<host>` so `iss` matches the IAM OIDC provider URL exactly.
- Retries cloudflared once if quick-tunnel assignment is throttled.
- Keeps `/token` behind `SECRET` (default `labsecret`), so the public tunnel
  can't be used to mint tokens by strangers.

Env knobs: `PORT`, `SECRET`, `KEY_DIR`, `ISSUER`.

**Stability caveat:** quick-tunnel hostnames change every restart → you must
re-register the IAM OIDC provider + role trust if it changes. For a stable URL:

- **Named tunnel + your own domain (free Cloudflare plan):** `cloudflared`
  tunnel config routes `idp.example.com` → `localhost:8765`. Then run
  `ISSUER=https://idp.example.com ./tunnel.sh` (starts only `idp.py`, using the
  stable hostname) alongside `cloudflared tunnel run <name>`.

## Failure experiments (each produces a real AWS error/deny)

| Mutate | Expected |
|---|---|
| wrong `aud` / wrong `iss` | `InvalidIdentityToken` / `Incorrect token audience` |
| expired `exp` | `InvalidIdentityToken` |
| tamper payload or signature | `InvalidIdentityToken` (signature check fails) |
| rotate key on server but reuse old token | fetch of new JWKS; old-kid signature fails |
| drop `sts:TagSession` from trust policy | tagged assumption denied |
| tag value mismatch in ABAC policy | `AccessDenied` on the gated action |

## Observing JWKS caching

`idp.py` logs every JWKS fetch with a timestamp. With `--cache "public, max-age=300"`
(default) STS should fetch occasionally; switch to `--cache no-store` to see a
fetch on (nearly) every call — exactly the behavior AWS documents.
