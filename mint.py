#!/usr/bin/env python3
"""CLI to forge a signed JWT with arbitrary claims, including AWS session tags.

Session tags use the https://aws.amazon.com/tags claim namespace; STS maps
them to aws:PrincipalTag/<key> on the assumed session.

Examples:
  ./mint.py --sub alice --tag User-Grant=admin --tag Group-Grant=devs --transitive User-Grant,Group-Grant --print-payload
  ./mint.py --iss https://lab.example.com --aud sts.amazonaws.com --sub svc \\
            --tag User-Grant=admin --transitive User-Grant --claims '{"custom": "x"}'
"""

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import jwt as jwtlib

KID = "idp-rsa-2048-1"
TAGS_NS = "https://aws.amazon.com/tags"
SOURCE_IDENTITY_NS = "https://aws.amazon.com/source_identity"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--key", default=str(Path(__file__).parent / "keys" / "private.pem"))
    ap.add_argument("--iss", default="http://localhost:8765")
    ap.add_argument("--aud", default="sts.amazonaws.com")
    ap.add_argument("--sub", default="lab-user")
    ap.add_argument("--ttl", type=int, default=3600, help="token lifetime in seconds")
    ap.add_argument("--kid", default=KID)
    ap.add_argument("--tag", action="append", default=[], metavar="KEY=VALUE",
                    help="session tag claim (repeatable)")
    ap.add_argument("--transitive", default="",
                    help="comma-separated tag keys to mark transitive (persist across role chaining)")
    ap.add_argument("--source-identity", default=None,
                    help="source identity claim (appears in CloudTrail as sourceIdentity)")
    ap.add_argument("--claims", default=None, help="extra JSON claims to merge into the payload")
    ap.add_argument("--print-payload", action="store_true", help="dump payload to stderr")
    args = ap.parse_args()

    now = int(time.time())
    payload = {
        "iss": args.iss,
        "aud": args.aud,
        "sub": args.sub,
        "iat": now,
        "exp": now + args.ttl,
        "jti": uuid.uuid4().hex,
    }

    if args.claims:
        payload.update(json.loads(args.claims))

    if args.tag:
        principal_tags = {}
        for kv in args.tag:
            key, _, value = kv.partition("=")
            principal_tags.setdefault(key, []).append(value)
        tags = {"principal_tags": principal_tags}
        transitive = [k for k in args.transitive.split(",") if k]
        if transitive:
            tags["transitive_tag_keys"] = transitive
        payload[TAGS_NS] = tags

    if args.source_identity is not None:
        payload[SOURCE_IDENTITY_NS] = args.source_identity

    token = jwtlib.sign_jwt({"alg": "RS256", "typ": "JWT", "kid": args.kid}, payload, args.key)
    print(token)
    if args.print_payload:
        print(json.dumps(payload, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
