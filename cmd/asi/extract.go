package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"asi/internal/targets"
	"asi/internal/targetsai"
)

// asi targets-extract: free text (inventory, notes, e-mail) -> targets in ASI CSV/JSON.
func cmdTargetsExtract(args []string) {
	fs := flag.NewFlagSet("targets-extract", flag.ExitOnError)
	in := fs.String("in", "-", "input text file (- = stdin)")
	out := fs.String("out", "-", "output file (- = stdout); .json writes JSON, otherwise CSV")
	format := fs.String("format", "", "csv or json (default: from -out extension, else csv)")
	engine := fs.String("engine", "auto", "auto (LLM if DEEPSEEK_API_KEY set, else regex), llm, regex")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: asi targets-extract [-in notes.txt] [-out targets/targets.csv] [-engine auto|llm|regex]")
		fmt.Fprintln(os.Stderr, "Reads free text and proposes targets in the ASI format. Review before scanning.")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	var r io.Reader = os.Stdin
	if *in != "-" {
		f, err := os.Open(*in)
		must(err)
		defer f.Close()
		r = f
	}
	text, err := io.ReadAll(io.LimitReader(r, targetsai.MaxInput+1))
	must(err)
	res, err := targetsai.Extract(context.Background(), targetsai.FromEnv(), string(text), *engine)
	must(err)
	for _, w := range res.Warnings {
		log.Printf("uwaga: %s", w)
	}
	on := 0
	for _, t := range res.Targets {
		if t.Enabled {
			on++
		}
	}
	log.Printf("silnik %s: %d cel(e), %d do skanowania", res.Engine, len(res.Targets), on)

	f := *format
	if f == "" {
		f = "csv"
		if len(*out) > 5 && (*out)[len(*out)-5:] == ".json" {
			f = "json"
		}
	}
	var body []byte
	if f == "json" {
		body, _ = json.MarshalIndent(targets.File{Version: 1, Targets: res.Targets}, "", "  ")
		body = append(body, '\n')
	} else {
		body = []byte(targetsai.CSV(res.Targets))
	}
	if *out == "-" {
		os.Stdout.Write(body)
		return
	}
	must(os.WriteFile(*out, body, 0o600))
	log.Printf("zapisano %s", *out)
}
