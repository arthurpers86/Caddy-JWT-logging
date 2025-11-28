FROM --platform=linux/amd64 caddy:2.10.2-builder AS builder

COPY caddy-jwt-logger /usr/src/app/caddy-jwt-logger

RUN xcaddy build \
    --with caddy-jwt-logger=/usr/src/app/caddy-jwt-logger

FROM caddy:2.10.2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
