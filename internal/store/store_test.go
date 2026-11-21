package store

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"asi/internal/obs"
	"asi/internal/targets"
)

// Integration test: runs only with ASI_TEST_DATABASE_URL (e.g. the dev asi-db).
//   ASI_TEST_DATABASE_URL=$ASI_DATABASE_URL go test ./internal/store/
func testStore(t *testing.T, s Sealer) *Store {
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ASI_TEST_DATABASE_URL not set")
	}
	st, err := Open(context.Background(), url, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

// xorSealer proves that data really goes through the Sealer (not stored in plain text).
type xorSealer struct{}

func (xorSealer) Seal(b []byte) ([]byte, error) { return xor(b), nil }
func (xorSealer) Open(b []byte) ([]byte, error) { return xor(b), nil }
func xor(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[i] = b[i] ^ 0x5a
	}
	return o
}

func TestRunRoundTrip(t *testing.T) {
	st := testStore(t, xorSealer{})
	ctx := context.Background()
	id := fmt.Sprintf("test-%d", time.Now().UnixNano())
	t.Cleanup(func() { st.DB.Exec(ctx, `DELETE FROM runs WHERE id=$1`, id) })

	if err := st.CreateRun(ctx, id, "test", "manual", map[string]int{"parallel": 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.StartChunk(ctx, id, "services", 0, []string{"192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	in := []obs.Observation{
		obs.New(obs.KindHost, "192.0.2.10", "nmap", obs.HostData{Up: true}, 100, "up"),
		obs.New(obs.KindService, "192.0.2.10/tcp/443", "nmap", obs.ServiceData{Name: "http", Product: "nginx"}, 100, "http", "nginx"),
	}
	if err := st.InsertObservations(ctx, id, "services", 0, in); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishChunk(ctx, id, "services", 0, "done", time.Second, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishRun(ctx, id, "completed", map[string]int{"open": 1}); err != nil {
		t.Fatal(err)
	}
	out, err := st.Observations(ctx, id, obs.KindService)
	if err != nil || len(out) != 1 {
		t.Fatalf("observations: %v %d", err, len(out))
	}
	var d obs.ServiceData
	if err := out[0].Decode(&d); err != nil || d.Product != "nginx" {
		t.Fatalf("decrypted data: %v %+v", err, d)
	}
	var raw []byte
	st.DB.QueryRow(ctx, `SELECT data_enc FROM observations WHERE run_id=$1 AND kind='service'`, id).Scan(&raw)
	if bytes.Contains(raw, []byte("nginx")) {
		t.Fatal("data_enc stored in plain text")
	}
	up, _ := st.LiveHosts(ctx, id)
	if len(up) != 1 || up[0] != "192.0.2.10" {
		t.Fatalf("live hosts: %v", up)
	}
}

func TestTargetsUpsert(t *testing.T) {
	st := testStore(t, xorSealer{})
	ctx := context.Background()
	set := fmt.Sprintf("test-%d", time.Now().UnixNano())
	t.Cleanup(func() { st.DB.Exec(ctx, `DELETE FROM target_sets WHERE name=$1`, set) })
	ts := []targets.Target{{Target: "192.0.2.0/30", Tags: []string{"lab"}, Enabled: true, Note: "secret note"},
		{Target: "www.example.org", Enabled: false}}
	if n, err := st.UpsertTargets(ctx, set, ts); err != nil || n != 2 {
		t.Fatalf("upsert: %v %d", err, n)
	}
	ts[0].Note = "changed" // edit survives as update, not duplicate
	if _, err := st.UpsertTargets(ctx, set, ts[:1]); err != nil {
		t.Fatal(err)
	}
	got, err := st.Targets(ctx, set)
	if err != nil || len(got) != 2 || got[0].Note != "changed" || got[1].Enabled {
		t.Fatalf("targets: %v %+v", err, got)
	}
}
