package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"asi/internal/store"
)

// cmdUser manages panel users (RBAC is local only - mentor: one admin is enough,
// more users from the GUI). It exists mainly for recovery: the admin account is
// seeded from .env only when the users table is empty, so after a password change
// in .env (or a lost password) there is no other way back in.
//
//	asi user list
//	asi user passwd -user admin -password 'new-secret'
//	asi user add -user jury -password 'viewer-pass' -role viewer
func cmdUser(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: asi user <list|passwd|add> [-db URL] [-user U] [-password P] [-role ROLE]")
		os.Exit(2)
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("user "+sub, flag.ExitOnError)
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL (env ASI_DATABASE_URL)")
	user := fs.String("user", "", "username")
	pass := fs.String("password", "", "new password (min. 10 characters)")
	role := fs.String("role", "viewer", "role: viewer | analyst | operator | admin")
	fs.Parse(args)
	if *url == "" {
		log.Fatal("set ASI_DATABASE_URL or -db")
	}
	ctx := context.Background()
	st, err := openStore(ctx, *url)
	must(err)
	defer st.Close()

	switch sub {
	case "list":
		us, err := st.Users(ctx)
		must(err)
		for _, u := range us {
			state := "active"
			if u.Disabled {
				state = "disabled"
			}
			fmt.Printf("%-20s %-9s %s\n", u.Username, u.Role, state)
		}
	case "passwd":
		if *user == "" || *pass == "" {
			log.Fatal("usage: asi user passwd -user NAME -password NEW (min. 10 znakow)")
		}
		u, err := st.SetPassword(ctx, *user, *pass)
		must(err)
		log.Printf("user %q: password changed (role %s)", u.Username, u.Role)
	case "add":
		if *user == "" || *pass == "" {
			log.Fatal("usage: asi user add -user NAME -password PASS -role ROLE")
		}
		if store.RoleLevel[strings.ToLower(*role)] == 0 {
			log.Fatalf("unknown role %q (viewer|analyst|operator|admin)", *role)
		}
		u, err := st.CreateUser(ctx, *user, *pass, strings.ToLower(*role))
		must(err)
		log.Printf("user %q created (role %s)", u.Username, u.Role)
	default:
		log.Fatalf("unknown: asi user %s", sub)
	}
}
