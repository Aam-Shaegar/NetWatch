package sensorrpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	wire "netwatch.local/netwatch/contracts/sensorv1"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/store"
	"netwatch.local/netwatch/internal/transport"
)

func TestEnrollmentAndDeliveryLifecycle(t *testing.T) {
	base := os.Getenv("NETWATCH_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("requires a disposable PostgreSQL database")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "test_sensor_" + hex.EncodeToString(suffix[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
	dsn, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	db, err := store.Open(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	service := &service{db: db, modelID: "test", policyVersion: "v1", log: slog.Default()}
	invite, err := db.CreateSensorRegistration(ctx, "sensor-lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.Repeat("f", 64)
	enroll := &wire.EnrollRequest{SchemaVersion: transport.SensorProtocolVersion, RegistrationCode: invite.Code, Credential: credential}
	identity, err := service.Enroll(ctx, enroll)
	if err != nil || identity.GetSensorId() != invite.ID {
		t.Fatalf("enrollment failed: %v", err)
	}
	if _, err := service.Enroll(ctx, enroll); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("used registration code must be rejected: %v", err)
	}

	authed := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+credential))
	t.Run("resource samples are optional and scoped to authenticated pilots", func(t *testing.T) {
		sample := &wire.ProcessResources{CpuPct: 12.5, RssBytes: 1 << 20}
		req := &wire.ContactRequest{SchemaVersion: 1, Resources: sample}
		checkCount := func(want int) {
			t.Helper()
			var count int
			if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM sensor_resource_samples").Scan(&count); err != nil || count != want {
				t.Fatalf("resource sample count %d, want %d: %v", count, want, err)
			}
		}
		if _, err := service.Contact(authed, req); err != nil {
			t.Fatal(err)
		}
		checkCount(0)
		if _, err := db.StartPilot(ctx, "campus", "test", "v1"); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Contact(ctx, req); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("unauthenticated resource sample: %v", err)
		}
		sample.CpuPct = math.NaN()
		if _, err := service.Contact(authed, req); err != nil {
			t.Fatalf("invalid optional metrics interrupted contact: %v", err)
		}
		checkCount(0)
		sample.CpuPct = 12.5
		for i := 0; i < 3; i++ {
			if _, err := service.Contact(authed, req); err != nil {
				t.Fatal(err)
			}
		}
		var total, buckets, matching int
		err := db.Pool.QueryRow(ctx, `SELECT count(*),count(DISTINCT date_trunc('minute',sampled_at)),
			count(*) FILTER (WHERE sensor_id=$1 AND cpu_pct=12.5 AND rss_bytes=1048576)
			FROM sensor_resource_samples`, invite.ID).Scan(&total, &buckets, &matching)
		if err != nil || total == 0 || total != buckets || total != matching {
			t.Fatalf("unexpected resource samples: total=%d buckets=%d matching=%d: %v", total, buckets, matching, err)
		}
		// Even if the optional telemetry store fails, the control heartbeat
		// must return the state so a live capture can continue.
		if _, err := db.Pool.Exec(ctx, "ALTER TABLE sensor_resource_samples RENAME TO unavailable_samples"); err != nil {
			t.Fatal(err)
		}
		if contact, err := service.Contact(authed, req); err != nil || contact.GetState() != "active" {
			t.Fatalf("resource storage failure interrupted control heartbeat: %v", err)
		}
	})
	raw, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var w contract.Window
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	start, _ := strconv.ParseInt(w.WindowStartNS, 10, 64)
	end, _ := strconv.ParseInt(w.WindowEndNS, 10, 64)
	features := make(map[string]*wire.FeatureValue, len(w.Features)+5)
	for name, value := range w.Features {
		features[name] = &wire.FeatureValue{Value: value}
	}
	for _, name := range []string{"in_tcp_distinct_ports_per_source_max", "in_udp_packets", "in_udp_ip_bytes", "in_icmp_packets", "in_icmp_ip_bytes"} {
		features[name] = &wire.FeatureValue{Value: new(float64)}
	}
	request := &wire.SubmitRequest{
		SchemaVersion: 1, BatchId: strings.Repeat("a", 64), QueueLoss: &wire.QueueLoss{},
		Observations: []*wire.Observation{{
			SchemaVersion: 1, FeatureSetVersion: contract.TrafficV3, EventId: w.EventID,
			SensorId: invite.ID, CaptureEpoch: w.CaptureEpoch, EntityId: w.EntityID,
			EntityType: "host", WindowStartNs: start, WindowEndNs: end,
			Features: features, Quality: &wire.Quality{Coverage: "complete", CaptureDropped: new(int64)},
		}},
	}
	if err := db.SetSensorState(ctx, invite.ID, "pause"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Submit(authed, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("paused sensor can submit: %v", err)
	}
	contact, err := service.Contact(authed, &wire.ContactRequest{SchemaVersion: 1})
	if err != nil || contact.GetState() != "paused" {
		t.Fatalf("paused sensor cannot receive its state: %v", err)
	}
	if err := db.SetSensorState(ctx, invite.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		ack, err := service.Submit(authed, request)
		if err != nil || len(ack.GetAcceptedEventIds()) != 1 || ack.GetAcceptedEventIds()[0] != w.EventID {
			t.Fatalf("submission attempt %d did not acknowledge observation: %v", attempt+1, err)
		}
	}
	if err := db.SetSensorState(ctx, invite.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Contact(authed, &wire.ContactRequest{SchemaVersion: 1}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked credential still works: %v", err)
	}
}
