cloudflared tunnel login
cloudflared tunnel create oidc
cloudflared tunnel route dns oidc oidc.compulty.com
cloudflared tunnel run --url http://localhost:8765 oidc
# ISSUER=https://oidc.compulty.com ./tunnel.sh

