# local managed (adv tier or local dev)
cloudflared tunnel login
cloudflared tunnel create oidc
cloudflared tunnel route dns oidc oidc.compulty.com
cloudflared tunnel run --url http://localhost:8765 oidc
# ISSUER=https://oidc.compulty.com ./tunnel.sh

- tunnel routing doesn't perform healthcheck over app backend, as long as the tunnel appears running, cloudflare will continue sending traffic
  - cloudflared service would create blackhole
  - prefer `cloudflared tunnel run` over service
  - leverage k8s pod/docker compose to manage the lifecycle of tunnel + app
    - have the app manage the tunnel running together
- cloudflared tunnel token vs tunnel creds
  - credentials file works well for multiple tunnels on one host (using local config)
    - advance setup with pay tier
  - tunnel token is for managed routing (zero touch) and the route get push to tunnel client
    - most flexible as free tunneling does no healthcheck and load balancing at all, this is prefer

brew services start cloudflared
- uses user account