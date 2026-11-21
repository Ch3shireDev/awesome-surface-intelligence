package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"asi/internal/importer"
)

// asi import FILE... - results of scans made elsewhere (nmap XML, JSON, CSV, httpx/nuclei JSONL)
func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL")
	coverage := fs.String("coverage", "auto", "auto (hosts/ports in the file count as scanned) | none (only add observations)")
	at := fs.String("at", "", "when the scan happened, RFC3339 (default: now)")
	rc := reconcileFlags(fs)
	fs.Parse(args)
	if fs.NArg() == 0 {
		log.Fatal("usage: asi import [-coverage auto|none] [-at 2026-11-21T10:00:00Z] FILE...")
	}
	st := dbOrDie(*url)
	defer st.Close()
	o := importer.Options{Coverage: *coverage, Reconcile: *rc}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		must(err)
		o.At = t
	}
	for _, f := range fs.Args() {
		data, err := os.ReadFile(f)
		must(err)
		s, err := importer.Import(context.Background(), st, filepath.Base(f), data, o)
		if err != nil {
			log.Fatalf("%s: %v", f, err)
		}
		b, _ := json.Marshal(s)
		fmt.Println(string(b))
		o.At = time.Time{} // next file: now (unique run id needs a new second)
		time.Sleep(1100 * time.Millisecond)
	}
}
