package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"asi/internal/store"
	"asi/internal/targets"
	"asi/internal/targetsai"
)

// asi mcp: Model Context Protocol server over stdio (JSON-RPC 2.0, one message per
// line). Lets an AI client (Claude Code, Claude Desktop, ...) turn free text into ASI
// targets and save them to the database. Logs go to stderr; stdout is the protocol.
//
//	claude mcp add asi -- /path/to/asi mcp -env /path/to/asi/.env
func cmdMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	envFile := fs.String("env", ".env", "load variables missing from the environment from this file (if it exists)")
	fs.Parse(args)
	log.SetOutput(os.Stderr)
	loadEnvFile(*envFile)

	s := &mcpServer{ai: targetsai.FromEnv()}
	defer func() {
		if s.st != nil {
			s.st.Close()
		}
	}()
	in := bufio.NewReader(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		line, err := in.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			if resp := s.handle(line); resp != nil {
				enc.Encode(resp)
			}
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Fatal(err)
		}
	}
}

// loadEnvFile sets KEY=VALUE pairs from a dotenv file without overriding the environment.
func loadEnvFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(l, "export "), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
}

type mcpServer struct {
	ai targetsai.Config
	st *store.Store
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

func (s *mcpServer) handle(line []byte) *rpcResp {
	var req rpcReq
	if err := json.Unmarshal(line, &req); err != nil {
		return &rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{-32700, "parse error"}}
	}
	if req.ID == nil { // notification (e.g. notifications/initialized)
		return nil
	}
	resp := &rpcResp{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = "2025-06-18"
		}
		resp.Result = map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "asi", "version": "0.1"},
			"instructions": "ASI (Attack Surface Intelligence). extract_targets zamienia dowolny tekst (inwentarz, notatki) na cele " +
				"w formacie ASI; zawsze pokaż wynik użytkownikowi przed add_targets. Cele z enabled=false nie są skanowane.",
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": mcpTools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcErr{-32602, "invalid params"}
			break
		}
		out, err := s.call(context.Background(), p.Name, p.Arguments)
		if err != nil {
			resp.Result = map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": err.Error()}}}
			break
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		resp.Result = map[string]any{"content": []map[string]string{{"type": "text", "text": string(b)}}, "structuredContent": out}
	default:
		resp.Error = &rpcErr{-32601, "method not found: " + req.Method}
	}
	return resp
}

var targetSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"target":  map[string]string{"type": "string", "description": "IP, CIDR albo domena"},
		"asset":   map[string]string{"type": "string"},
		"owner":   map[string]string{"type": "string"},
		"tags":    map[string]any{"type": "array", "items": map[string]string{"type": "string"}},
		"enabled": map[string]string{"type": "boolean", "description": "false = nigdy nie skanuj"},
		"note":    map[string]string{"type": "string"},
	},
	"required": []string{"target"},
}

var mcpTools = []map[string]any{
	{
		"name": "extract_targets",
		"description": "Zamienia dowolny tekst (inwentarz serwerów, tabelę, notatki, mail) na listę celów skanowania w formacie ASI " +
			"(target, asset, owner, tags, enabled, note) i CSV. Używa DeepSeek (deepseek-flash), bez klucza prostego wyszukiwania adresów. " +
			"Odrzuca cele, których nie ma w tekście; adresy wewnętrzne/Tailscale zawsze enabled=false. Niczego nie zapisuje.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text":   map[string]string{"type": "string", "description": "tekst źródłowy (do 64 KB)"},
				"engine": map[string]any{"type": "string", "enum": []string{"auto", "llm", "regex"}, "default": "auto"},
			},
			"required": []string{"text"},
		},
		"annotations": map[string]any{"readOnlyHint": true, "openWorldHint": true},
	},
	{
		"name":        "list_target_sets",
		"description": "Lista zbiorów celów w bazie ASI.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name":        "list_targets",
		"description": "Cele w zbiorze (domyślnie 'default').",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"set": map[string]string{"type": "string"}}},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name": "add_targets",
		"description": "Zapisuje cele do zbioru w bazie ASI (scalanie: puste pola nie kasują istniejących tagów i notatek). " +
			"Przed wywołaniem pokaż listę użytkownikowi. Cele są walidowane (IP, CIDR, domena).",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"set":     map[string]string{"type": "string", "description": "nazwa zbioru, domyślnie 'default'"},
				"targets": map[string]any{"type": "array", "items": targetSchema},
			},
			"required": []string{"targets"},
		},
		"annotations": map[string]any{"destructiveHint": false, "idempotentHint": true},
	},
}

func (s *mcpServer) store(ctx context.Context) (*store.Store, error) {
	if s.st != nil {
		return s.st, nil
	}
	url := os.Getenv("ASI_DATABASE_URL")
	if url == "" {
		return nil, fmt.Errorf("brak ASI_DATABASE_URL (uruchom z -env /ścieżka/do/asi/.env)")
	}
	st, err := openStore(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("baza ASI: %w", err)
	}
	s.st = st
	return st, nil
}

func setOr(v string) string {
	if v = strings.TrimSpace(v); v == "" {
		return "default"
	}
	return v
}

func (s *mcpServer) call(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	switch name {
	case "extract_targets":
		var a struct{ Text, Engine string }
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		r, err := targetsai.Extract(ctx, s.ai, a.Text, a.Engine)
		if err != nil {
			return nil, err
		}
		return map[string]any{"engine": r.Engine, "warnings": r.Warnings, "targets": r.Targets, "csv": targetsai.CSV(r.Targets)}, nil
	case "list_target_sets":
		st, err := s.store(ctx)
		if err != nil {
			return nil, err
		}
		sets, err := st.TargetSets(ctx)
		return map[string]any{"sets": sets}, err
	case "list_targets":
		var a struct{ Set string }
		json.Unmarshal(raw, &a)
		st, err := s.store(ctx)
		if err != nil {
			return nil, err
		}
		ts, err := st.Targets(ctx, setOr(a.Set))
		return map[string]any{"set": setOr(a.Set), "targets": ts}, err
	case "add_targets":
		var a struct {
			Set     string
			Targets []struct {
				Target, Asset, Owner, Note string
				Tags                       []string
				Enabled                    *bool
			}
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		var ok []targets.Target
		var bad []string
		for _, t := range a.Targets {
			v := strings.TrimSpace(t.Target)
			if err := targetsai.Valid(v); err != nil {
				bad = append(bad, err.Error())
				continue
			}
			ok = append(ok, targets.Target{Target: v, Asset: t.Asset, Owner: t.Owner, Tags: t.Tags, Note: t.Note,
				Enabled: t.Enabled == nil || *t.Enabled})
		}
		st, err := s.store(ctx)
		if err != nil {
			return nil, err
		}
		n, err := st.MergeTargets(ctx, setOr(a.Set), ok)
		if err != nil {
			return nil, err
		}
		st.Audit(ctx, nil, "targets_add_mcp", "target_set", setOr(a.Set), map[string]any{"written": n, "rejected": len(bad)})
		return map[string]any{"set": setOr(a.Set), "written": n, "rejected": bad}, nil
	}
	return nil, fmt.Errorf("nieznane narzędzie %q", name)
}
