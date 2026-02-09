package main

import (
	"net/http"

	"go.uber.org/zap"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/getsentry/sentry-go"
)

var logger *zap.Logger

func init() {
	logger, _ = zap.NewProduction()
	sentry.Init(sentry.ClientOptions{
		Dsn: "https://examplePublicKey@o0.ingest.sentry.io/0",
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if !authenticate(username, password) {
		logger.Warn("authentication failure",
			zap.String("username", username),
			zap.String("ip", r.RemoteAddr),
		)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	logger.Info("login successful", zap.String("username", username))
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		logger.Warn("permission denied: non-admin user attempted admin access",
			zap.String("user", getUserID(r)),
		)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
}

func metricsHandler() http.Handler {
	return promhttp.Handler()
}

func authenticate(username, password string) bool { return false }
func isAdmin(r *http.Request) bool                { return false }
func getUserID(r *http.Request) string             { return "" }
