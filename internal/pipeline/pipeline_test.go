package pipeline_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/api"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/spool"
	"netwatch.local/netwatch/internal/store"
	"netwatch.local/netwatch/internal/transport"
	"netwatch.local/netwatch/internal/worker"
	"netwatch.local/netwatch/migrations"
)

const sensor = "sensor-a"

var token = strings.Repeat("a", 32)

func database(t *testing.T) (*store.Store, string) {
	t.Helper()
	base := os.Getenv("NETWATCH_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("real PostgreSQL: run make server-smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal("test PostgreSQL unavailable")
	}
	var id [8]byte
	rand.Read(id[:])
	schema := "test_" + hex.EncodeToString(id[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE")
		if err != nil {
			t.Error("test schema cleanup failed")
		}
		admin.Close(cleanup)
	})
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return db, u.String()
}
func window(t *testing.T, id string, end time.Time) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var w contract.Window
	json.Unmarshal(raw, &w)
	w.SensorID = sensor
	w.EventID = id
	w.CaptureEpoch = "integration"
	w.WindowStartNS = fmt.Sprint(end.Add(-5 * time.Second).UnixNano())
	w.WindowEndNS = fmt.Sprint(end.UnixNano())
	raw, err = json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func batch(t *testing.T, windows ...json.RawMessage) transport.Batch {
	t.Helper()
	items := []spool.Item{}
	for _, raw := range windows {
		var w contract.Window
		json.Unmarshal(raw, &w)
		items = append(items, spool.Item{Window: raw, EventID: w.EventID})
	}
	b, err := transport.NewBatch(items, spool.Loss{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func handler(t *testing.T, db *store.Store) http.Handler {
	t.Helper()
	h, err := api.New(api.Config{Store: db, Tokens: map[string]string{sensor: token, "other": strings.Repeat("b", 32)}, ModelID: "test-model", PolicyVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func post(h http.Handler, b transport.Batch, credential string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(b)
	r := httptest.NewRequest("POST", "/v1/windows", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+credential)
	r.Header.Set("Idempotency-Key", b.BatchID)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	return out
}
func count(t *testing.T, db *store.Store, table string) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(context.Background(), "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func ingest(t *testing.T, db *store.Store, windows ...json.RawMessage) {
	t.Helper()
	if err := db.Ingest(context.Background(), batch(t, windows...), sensor, "test-model", "v1"); err != nil {
		t.Fatal(err)
	}
}
func prediction(j store.Job) contract.Prediction {
	score, threshold := 0.1, 0.5
	return contract.Prediction{SchemaVersion: 1, EventID: j.EventID, ModelID: j.ModelID, FeatureSetVersion: "traffic-v1", Status: "normal", Score: &score, Threshold: &threshold}
}
func model(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := ioRead(r)
		if err != nil {
			t.Error(err)
			return
		}
		if contract.Validate("inference-request", raw) != nil {
			t.Error("invalid ML request")
			w.WriteHeader(400)
			return
		}
		var req worker.Request
		json.Unmarshal(raw, &req)
		var window contract.Window
		json.Unmarshal(req.Windows[0], &window)
		calls.Add(1)
		p := prediction(store.Job{EventID: window.EventID, ModelID: req.ModelID})
		json.NewEncoder(w).Encode(worker.Response{SchemaVersion: 1, Predictions: []contract.Prediction{p}})
	}))
	t.Cleanup(s.Close)
	return s
}
func newWorker(t *testing.T, db *store.Store, endpoint string) *worker.Worker {
	t.Helper()
	c := worker.DefaultConfig()
	c.Endpoint = endpoint
	w, err := worker.New(db, c)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestMigrationAndAtomicIngestion(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	h := handler(t, db)
	b := batch(t, window(t, "first", time.Now()), window(t, "second", time.Now()))
	if got := post(h, b, "bad").Code; got != 401 {
		t.Fatal(got)
	}
	if got := post(h, b, strings.Repeat("b", 32)).Code; got != 403 {
		t.Fatal(got)
	}
	broken := b
	broken.Windows = append([]json.RawMessage(nil), b.Windows...)
	broken.Windows[1] = json.RawMessage(`{}`)
	out := post(h, broken, token)
	if out.Code != 422 {
		t.Fatal(out.Code, out.Body.String())
	}
	var rejection transport.Rejection
	json.Unmarshal(out.Body.Bytes(), &rejection)
	if rejection.ErrorIndex == nil || *rejection.ErrorIndex != 1 {
		t.Fatal(rejection)
	}
	if count(t, db, "feature_windows") != 0 || count(t, db, "ingestion_batches") != 0 {
		t.Fatal("invalid batch partially committed")
	}
	out = post(h, b, token)
	if out.Code != 200 {
		t.Fatal(out.Code, out.Body.String())
	}
	var ack transport.Ack
	json.Unmarshal(out.Body.Bytes(), &ack)
	if ack.BatchID != b.BatchID || len(ack.AcceptedEventIDs) != 2 {
		t.Fatal(ack)
	}
	results := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func() { results <- post(h, b, token).Code }()
	}
	for i := 0; i < 8; i++ {
		if status := <-results; status != 200 {
			t.Fatal(status)
		}
	}
	if count(t, db, "feature_windows") != 2 || count(t, db, "inference_jobs") != 2 || count(t, db, "ingestion_batches") != 1 {
		t.Fatal("duplicate ingestion")
	}
	if err := db.Ingest(ctx, b, sensor, "new-model", "new-policy"); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "inference_jobs") != 2 {
		t.Fatal("retry changed inference target")
	}
	collision := batch(t, window(t, "third", time.Now()))
	collision.BatchID = b.BatchID
	if got := post(h, collision, token).Code; got != 409 {
		t.Fatal(got)
	}
	changed := append(json.RawMessage(nil), b.Windows[1]...)
	var value map[string]any
	json.Unmarshal(changed, &value)
	value["capture_epoch"] = "different"
	changed, _ = json.Marshal(value)
	conflict := batch(t, window(t, "aaa-new", time.Now()), changed)
	if got := post(h, conflict, token).Code; got != 409 {
		t.Fatal(got)
	}
	if count(t, db, "feature_windows") != 2 || count(t, db, "ingestion_batches") != 1 {
		t.Fatal("conflicting batch was partly committed")
	}
	req := httptest.NewRequest("GET", "/v1/windows/first", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 32))
	record := httptest.NewRecorder()
	h.ServeHTTP(record, req)
	if record.Code != 404 {
		t.Fatal("cross-sensor data visible")
	}
}
func TestAckWaitsForCommit(t *testing.T) {
	db, _ := database(t)
	_, err := db.Pool.Exec(context.Background(), `CREATE FUNCTION reject_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected commit failure'; END$$;
 CREATE CONSTRAINT TRIGGER fail_commit AFTER INSERT ON inference_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_commit()`)
	if err != nil {
		t.Fatal(err)
	}
	out := post(handler(t, db), batch(t, window(t, "rollback", time.Now())), token)
	if out.Code != 503 {
		t.Fatal("ACK escaped failed commit", out.Code, out.Body.String())
	}
	for _, table := range []string{"feature_windows", "inference_jobs", "ingestion_batches"} {
		if count(t, db, table) != 0 {
			t.Fatal("transaction not atomic", table)
		}
	}
}
func TestLeaseExpiryAndFencing(t *testing.T) {
	db, _ := database(t)
	ingest(t, db, window(t, "lease", time.Now()))
	ctx := context.Background()
	first, err := db.Claim(ctx, 250*time.Millisecond, false)
	if err != nil || first == nil {
		t.Fatal(first, err)
	}
	if other, err := db.Claim(ctx, time.Second, false); err != nil || other != nil {
		t.Fatal("double lease", other, err)
	}
	time.Sleep(300 * time.Millisecond)
	second, err := db.Claim(ctx, 5*time.Second, false)
	if err != nil || second == nil || second.Token == first.Token || second.Attempts != 2 {
		t.Fatal(second, err)
	}
	if err = db.Finish(ctx, *first, prediction(*first)); !errors.Is(err, store.ErrLeaseLost) {
		t.Fatal("stale result accepted", err)
	}
	if err = db.Retry(ctx, *first, time.Second, "stale"); !errors.Is(err, store.ErrLeaseLost) {
		t.Fatal("stale retry changed lease", err)
	}
	if err = db.Finish(ctx, *second, prediction(*second)); err != nil {
		t.Fatal(err)
	}
	if err = db.Finish(ctx, *second, prediction(*second)); !errors.Is(err, store.ErrLeaseLost) {
		t.Fatal(err)
	}
	if count(t, db, "predictions") != 1 {
		t.Fatal("duplicate result")
	}
	var status string
	db.Pool.QueryRow(ctx, `SELECT status FROM inference_jobs`).Scan(&status)
	if status != "done" {
		t.Fatal(status)
	}
}
func TestSenderToPostgresToML(t *testing.T) {
	db, _ := database(t)
	q, err := spool.Open(t.TempDir(), spool.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	raw := window(t, "end-to-end", time.Now())
	if err = q.Append(raw); err != nil {
		t.Fatal(err)
	}
	receiver := httptest.NewServer(handler(t, db))
	defer receiver.Close()
	config := transport.DefaultConfig()
	config.Endpoint = receiver.URL + "/v1/windows"
	config.Token = token
	sender, err := transport.New(q, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = sender.Run(ctx, true); err != nil {
		t.Fatal(err)
	}
	if q.Stats().Pending != 0 || count(t, db, "inference_jobs") != 1 {
		t.Fatal("delivery not committed")
	}
	var calls atomic.Int32
	ml := model(t, &calls)
	w := newWorker(t, db, ml.URL)
	if worked, err := w.Once(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	if calls.Load() != 1 || count(t, db, "predictions") != 1 {
		t.Fatal("prediction missing")
	}
	req := httptest.NewRequest("GET", "/v1/predictions/end-to-end", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	handler(t, db).ServeHTTP(out, req)
	if out.Code != 200 || !strings.Contains(out.Body.String(), `"test-model"`) {
		t.Fatal(out.Code, out.Body.String())
	}
}
func TestFreshPriorityAndBacklogFairness(t *testing.T) {
	db, _ := database(t)
	old := []json.RawMessage{}
	for i := 0; i < 10; i++ {
		old = append(old, window(t, fmt.Sprintf("old-%02d", i), time.Now().Add(-24*time.Hour+time.Duration(i)*time.Minute)))
	}
	ingest(t, db, old...)
	ingest(t, db, window(t, "fresh", time.Now()))
	order := make(chan string, 5)
	ml := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req worker.Request
		json.NewDecoder(r.Body).Decode(&req)
		var window contract.Window
		json.Unmarshal(req.Windows[0], &window)
		order <- window.EventID
		p := prediction(store.Job{EventID: window.EventID, ModelID: req.ModelID})
		json.NewEncoder(w).Encode(worker.Response{SchemaVersion: 1, Predictions: []contract.Prediction{p}})
	}))
	defer ml.Close()
	w := newWorker(t, db, ml.URL)
	for i := 0; i < 5; i++ {
		if _, err := w.Once(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	first := <-order
	for i := 0; i < 3; i++ {
		<-order
	}
	fifth := <-order
	if first != "fresh" || fifth != "old-00" {
		t.Fatal(first, fifth)
	}
}
func TestUnavailableAndInvalidModelDoNotCreateNormal(t *testing.T) {
	for _, mode := range []string{"unavailable", "wrong-model", "bad-score", "timeout", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			db, _ := database(t)
			ingest(t, db, window(t, "retry", time.Now()))
			ml := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := ioRead(r)
				var req worker.Request
				json.Unmarshal(raw, &req)
				var window contract.Window
				json.Unmarshal(req.Windows[0], &window)
				p := prediction(store.Job{EventID: window.EventID, ModelID: req.ModelID})
				switch mode {
				case "unavailable":
					w.WriteHeader(503)
					return
				case "wrong-model":
					p.ModelID = "other"
				case "bad-score":
					p.Threshold = nil
				case "timeout":
					<-r.Context().Done()
					return
				case "oversized":
					w.Write(make([]byte, 65537))
					return
				}
				json.NewEncoder(w).Encode(worker.Response{SchemaVersion: 1, Predictions: []contract.Prediction{p}})
			}))
			defer ml.Close()
			c := worker.DefaultConfig()
			c.Endpoint = ml.URL
			c.Timeout = 50 * time.Millisecond
			w, err := worker.New(db, c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = w.Once(context.Background()); err != nil {
				t.Fatal(err)
			}
			if count(t, db, "predictions") != 0 {
				t.Fatal("failure became a prediction")
			}
			var status string
			var last *string
			db.Pool.QueryRow(context.Background(), `SELECT status,last_error FROM inference_jobs`).Scan(&status, &last)
			if status != "pending" || last == nil {
				t.Fatal(status, last)
			}
		})
	}
}
func TestWorkerSIGKILLAfterInference(t *testing.T) {
	db, url := database(t)
	ingest(t, db, window(t, "crash", time.Now()))
	var calls atomic.Int32
	ml := model(t, &calls)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashWorkerHelper$")
	cmd.Env = append(os.Environ(), "NETWATCH_CRASH_WORKER_DB="+url, "NETWATCH_CRASH_WORKER_ML="+ml.URL)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "inferred" {
		t.Fatal("worker did not reach inference boundary")
	}
	cmd.Process.Kill()
	_ = cmd.Wait()
	time.Sleep(300 * time.Millisecond)
	w := newWorker(t, db, ml.URL)
	if worked, err := w.Once(ctx); err != nil || !worked {
		t.Fatal(worked, err)
	}
	if calls.Load() != 2 || count(t, db, "predictions") != 1 {
		t.Fatal("crash recovery duplicated or lost result", calls.Load())
	}
}
func TestCrashWorkerHelper(t *testing.T) {
	url := os.Getenv("NETWATCH_CRASH_WORKER_DB")
	if url == "" {
		t.Skip("subprocess only")
	}
	db, err := store.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	j, err := db.Claim(context.Background(), 250*time.Millisecond, false)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	w := newWorker(t, db, os.Getenv("NETWATCH_CRASH_WORKER_ML"))
	if _, err = w.Infer(context.Background(), *j); err != nil {
		t.Fatal(err)
	}
	fmt.Println("inferred")
	for {
		time.Sleep(time.Hour)
	}
}
func TestMigrationRollbackAndReadiness(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	down, err := migrations.Files.ReadFile("000001_pipeline.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=1`)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.Ready(ctx); err == nil {
		t.Fatal("unmigrated schema ready")
	}
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db.Pool.Exec(ctx, `UPDATE schema_migrations SET checksum='changed'`)
	if err = db.Migrate(ctx); err == nil {
		t.Fatal("migration drift ignored")
	}
	out := httptest.NewRecorder()
	handler(t, db).ServeHTTP(out, httptest.NewRequest("GET", "/health/ready", nil))
	if out.Code != 503 {
		t.Fatal(out.Code)
	}
}

func ioRead(r *http.Request) ([]byte, error) { return io.ReadAll(r.Body) }

func TestConcurrentClaimsHaveOneOwnerEach(t *testing.T) {
	db, _ := database(t)
	raw := []json.RawMessage{}
	for i := 0; i < 8; i++ {
		raw = append(raw, window(t, fmt.Sprint(i), time.Now()))
	}
	ingest(t, db, raw...)
	results := make(chan *store.Job, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { j, err := db.Claim(context.Background(), 10*time.Second, false); results <- j; errs <- err }()
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		j := <-results
		if j == nil {
			t.Fatal("missing claim")
		}
		if seen[j.EventID] {
			t.Fatal("duplicate owner")
		}
		seen[j.EventID] = true
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
func TestPredictionAndCompletionCommitTogether(t *testing.T) {
	db, _ := database(t)
	ingest(t, db, window(t, "atomic-prediction", time.Now()))
	j, err := db.Claim(context.Background(), 30*time.Second, false)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	_, err = db.Pool.Exec(context.Background(), `CREATE FUNCTION reject_completion() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected completion failure'; END$$; CREATE CONSTRAINT TRIGGER fail_completion AFTER UPDATE ON inference_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_completion()`)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Finish(context.Background(), *j, prediction(*j)); err == nil {
		t.Fatal("injected failure ignored")
	}
	if count(t, db, "predictions") != 0 {
		t.Fatal("prediction escaped rollback")
	}
	db.Pool.Exec(context.Background(), `DROP TRIGGER fail_completion ON inference_jobs`)
	if err = db.Finish(context.Background(), *j, prediction(*j)); err != nil {
		t.Fatal(err)
	}
	if count(t, db, "predictions") != 1 {
		t.Fatal("retry did not finish")
	}
}
func TestHTTPBoundsAndFutureTimestamp(t *testing.T) {
	db, _ := database(t)
	h := handler(t, db)
	bad := batch(t, window(t, "bad\x00id", time.Now()))
	if got := post(h, bad, token).Code; got != 422 {
		t.Fatal("PostgreSQL-invalid value must be rejected before storage", got)
	}
	b := batch(t, window(t, "future", time.Now().Add(time.Hour)))
	if got := post(h, b, token).Code; got != 422 {
		t.Fatal(got)
	}
	r := httptest.NewRequest("POST", "/v1/windows", strings.NewReader(strings.Repeat(" ", (2<<20)+1)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 413 {
		t.Fatal(out.Code)
	}
	if count(t, db, "feature_windows") != 0 {
		t.Fatal("invalid request persisted")
	}
}
