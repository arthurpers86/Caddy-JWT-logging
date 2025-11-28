package jwtlogger

import (
  "net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JWTLogger{})
	httpcaddyfile.RegisterHandlerDirective("jwt_logger", parseCaddyfile)
}

type JWTLogger struct {
	logger *zap.Logger
}

func (JWTLogger) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jwt_logger",
		New: func() caddy.Module { return new(JWTLogger) },
	}
}

func (h *JWTLogger) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	return nil
}

func (h JWTLogger) Validate() error {
	return nil
}

func (h JWTLogger) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	authHeader := r.Header.Get("Authorization")

	if len(authHeader) > 7 && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		tokenString := strings.TrimSpace(authHeader[7:])

		token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			h.logger.Error("Failed to parse JWT", zap.Error(err))
		} else {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				exp, expOK := claims["exp"]
				iat, iatOK := claims["iat"]
				if expOK && iatOK {
					expFloat, expIsFloat := exp.(float64)
					iatFloat, iatIsFloat := iat.(float64)
					if expIsFloat && iatIsFloat {
						expTime := time.Unix(int64(expFloat), 0)
						iatTime := time.Unix(int64(iatFloat), 0)
						const oneYear = 365 * 24 * time.Hour
						if expTime.Sub(iatTime) > oneYear {
							host, _, err := net.SplitHostPort(r.RemoteAddr)
							if err != nil {
								host = r.RemoteAddr
							}
							fields := []zap.Field{zap.String("client_ip", host)}
							for k, v := range claims {
								fields = append(fields, zap.Any(k, v))
							}
							h.logger.Warn("JWT with lifetime longer than one year detected", fields...)
						}
					}
				}
			}
		}
	}
	return next.ServeHTTP(w, r)
}


func (h *JWTLogger) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m JWTLogger
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

var (
	_ caddy.Provisioner           = (*JWTLogger)(nil)
	_ caddy.Validator             = (*JWTLogger)(nil)
	_ caddyhttp.MiddlewareHandler = (*JWTLogger)(nil)
	_ caddyfile.Unmarshaler       = (*JWTLogger)(nil)
)
