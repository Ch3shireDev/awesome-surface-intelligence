package app

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"asi/internal/store"
	"asi/internal/targets"
)

// The analyst edits existing targets and schedules; PUT must never create one.
func TestAnalystCannotCreateThroughPUT(t *testing.T) {
	url := os.Getenv("ASI_DATABASE_URL")
	if url == "" {
		t.Skip("no ASI_DATABASE_URL")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	sfx := fmt.Sprint(time.Now().UnixNano())
	set, other, name, pass := "rbac-"+sfx, "rbac-other-"+sfx, "rbac"+sfx, "Analyst-test-"+sfx
	h := (&App{St: st, SessionTTL: time.Hour}).Handler()
	if _, err := st.MergeTargets(ctx, set, []targets.Target{{Target: "192.0.2.10", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	defer st.DeleteTargetSet(ctx, set, true)
	if _, err := st.CreateUser(ctx, name, pass, "analyst"); err != nil {
		t.Fatal(err)
	}
	defer st.DB.Exec(ctx, `UPDATE users SET disabled=true WHERE username=$1`, name)
	_, tok, err := st.Login(ctx, name, pass, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	put := func(path, body string) int {
		r := httptest.NewRequest("PUT", "/api/v1/"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	sched := func(id int64) string {
		return fmt.Sprintf(`{"id":%d,"name":"s%s","set":%q,"cron":"0 2 1 1 *","window_minutes":5,"enabled":false}`, id, sfx, set)
	}
	for _, id := range []string{"0", "-1", "abc", "999999999"} {
		if c := put("schedules/"+id, sched(0)); c < 400 {
			t.Errorf("PUT /schedules/%s = %d", id, c)
		}
	}
	var n int
	st.DB.QueryRow(ctx, `SELECT count(*) FROM schedules WHERE name=$1`, "s"+sfx).Scan(&n)
	if n != 0 {
		t.Fatalf("analyst created %d schedule(s)", n)
	}
	rows, err := st.TargetRows(ctx, set)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if c := put(fmt.Sprintf("targets/%d", rows[0].ID), fmt.Sprintf(`{"set":%q,"target":"192.0.2.10","owner":"edited","enabled":true}`, other)); c != 200 {
		t.Fatalf("legit edit = %d", c)
	}
	if ts, _ := st.Targets(ctx, other); len(ts) != 0 {
		t.Fatalf("analyst created set %s", other)
	}
	if ts, _ := st.Targets(ctx, set); len(ts) != 1 || ts[0].Owner != "edited" {
		t.Fatalf("edit did not land in the target's own set: %+v", ts)
	}
	sc, err := st.SaveSchedule(ctx, store.Schedule{Name: "edit" + sfx, Set: set, Cron: "0 2 1 1 *", WindowMinutes: 5}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Exec(ctx, `DELETE FROM schedules WHERE id=$1`, sc.ID)
	if c := put(fmt.Sprintf("schedules/%d", sc.ID), sched(sc.ID)); c != 200 {
		t.Fatalf("editing an existing schedule = %d", c)
	}
}
