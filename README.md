# Caddy-JWT-logging-
Caddy plugin to monitor JWT. A log is generated whenever a JWT with a lifetime longer than one year is detected.

In caddyfile :
```
route {
				jwt_logger
				reverse_proxy /* http://web:80
			}
```
