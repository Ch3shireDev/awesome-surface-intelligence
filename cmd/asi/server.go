package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"asi/internal/app"
)

// asi server - web GUI (DEV-4): dashboard, assets, target form, scans. Needs asi-db.
func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", envOr("ASI_WEB_ADDR", "127.0.0.1:8090"), "listen address (keep 127.0.0.1 unless behind TLS proxy)")
	live := fs.String("live", envOr("ASI_LIVE_ADDR", "127.0.0.1:8091"), "address of the live panel of a running scan")
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL (env ASI_DATABASE_URL)")
	results := fs.String("results", "results", "results directory")
	ttl := fs.Duration("session", 12*time.Hour, "session lifetime")
	secure := fs.Bool("secure-cookie", false, "set Secure on the session cookie (when served over HTTPS)")
	fs.Parse(args)
	if *url == "" {
		log.Fatal("asi server needs the database: set ASI_DATABASE_URL")
	}
	ctx := context.Background()
	st, err := openStore(ctx, *url)
	must(err)
	defer st.Close()

	// first admin from .env (mentor: one admin account is enough; more users from the GUI)
	if n, err := st.CountUsers(ctx); err == nil && n == 0 {
		user, pass := envOr("ASI_ADMIN_USER", "admin"), os.Getenv("ASI_ADMIN_PASSWORD")
		if pass == "" {
			b := make([]byte, 12)
			rand.Read(b)
			pass = hex.EncodeToString(b)
			log.Printf("ASI_ADMIN_PASSWORD not set - generated one-time password for %q: %s", user, pass)
		}
		if _, err := st.CreateUser(ctx, user, pass, "admin"); err != nil {
			log.Fatal(err)
		}
		log.Printf("created admin user %q", user)
	}

	self, err := os.Executable()
	must(err)
	wd, _ := os.Getwd()
	res, _ := filepath.Abs(*results)
	a := &app.App{St: st, ResultsDir: res, WorkDir: wd, Self: self, LiveAddr: *live, SessionTTL: *ttl, Secure: *secure}
	srv := &http.Server{Addr: *addr, Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("ASI web: http://%s", *addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
}
