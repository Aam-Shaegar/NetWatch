package sensorrpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	wire "netwatch.local/netwatch/contracts/sensorv1"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/store"
	"netwatch.local/netwatch/internal/transport"
)

type service struct {
	wire.UnimplementedSensorServiceServer
	db                     *store.Store
	modelID, policyVersion string
	log                    *slog.Logger
}

func NewServer(db *store.Store, modelID, policyVersion string, tlsConfig *tls.Config, log *slog.Logger) *grpc.Server {
	if log == nil {
		log = slog.Default()
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.MaxRecvMsgSize(transport.MaxGRPCMessage),
		grpc.MaxSendMsgSize(64<<10), grpc.MaxConcurrentStreams(32))
	wire.RegisterSensorServiceServer(s, &service{db: db, modelID: modelID, policyVersion: policyVersion, log: log})
	return s
}

func version(version uint32) error {
	if version != transport.SensorProtocolVersion {
		return status.Error(codes.FailedPrecondition, "unsupported sensor protocol version")
	}
	return nil
}

func validHexSecret(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func credentialFromContext(ctx context.Context) ([32]byte, error) {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) == 1 {
		value, ok := strings.CutPrefix(values[0], "Bearer ")
		if ok && validHexSecret(value) {
			return sha256.Sum256([]byte(value)), nil
		}
	}
	return [32]byte{}, status.Error(codes.Unauthenticated, "invalid sensor credential")
}

func (s *service) Enroll(ctx context.Context, req *wire.EnrollRequest) (*wire.ContactResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := version(req.GetSchemaVersion()); err != nil {
		return nil, err
	}
	if !validHexSecret(req.GetRegistrationCode()) || !validHexSecret(req.GetCredential()) ||
		req.GetRegistrationCode() == req.GetCredential() {
		s.log.Warn("sensor_registration_rejected")
		return nil, status.Error(codes.Unauthenticated, "registration rejected")
	}
	record, err := s.db.EnrollSensor(ctx, sha256.Sum256([]byte(req.GetRegistrationCode())), sha256.Sum256([]byte(req.GetCredential())))
	switch {
	case errors.Is(err, store.ErrSensorUnknown):
		s.log.Warn("sensor_registration_rejected")
		return nil, status.Error(codes.Unauthenticated, "registration rejected")
	case err != nil:
		s.log.Error("sensor_registration_storage_unavailable")
		return nil, status.Error(codes.Unavailable, "registration temporarily unavailable")
	}
	s.log.Info("sensor_registered", "sensor_id", record.ID)
	return &wire.ContactResponse{SchemaVersion: transport.SensorProtocolVersion, SensorId: record.ID, State: record.State}, nil
}

func (s *service) Contact(ctx context.Context, req *wire.ContactRequest) (*wire.ContactResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := version(req.GetSchemaVersion()); err != nil {
		return nil, err
	}
	token, err := credentialFromContext(ctx)
	if err != nil {
		return nil, err
	}
	loss, err := transport.LossFromWire(req.GetQueueLoss())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid queue loss")
	}
	record, err := s.db.ContactSensor(ctx, token, loss)
	if err != nil {
		return nil, s.transportError(err)
	}
	if sample := req.GetResources(); sample != nil {
		sampleCtx, stop := context.WithTimeout(ctx, 250*time.Millisecond)
		err := s.db.SaveSensorResources(sampleCtx, record.ID, sample.GetCpuPct(), sample.GetRssBytes())
		stop()
		if err != nil {
			s.log.Warn("sensor_resource_sample_unavailable", "sensor_id", record.ID)
		}
	}
	return &wire.ContactResponse{SchemaVersion: transport.SensorProtocolVersion, SensorId: record.ID, State: record.State}, nil
}

func (s *service) Submit(ctx context.Context, req *wire.SubmitRequest) (*wire.SubmitResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := version(req.GetSchemaVersion()); err != nil {
		return nil, err
	}
	token, err := credentialFromContext(ctx)
	if err != nil {
		return nil, err
	}
	batchID, observations := req.GetBatchId(), req.GetObservations()
	loss, err := transport.LossFromWire(req.GetQueueLoss())
	if !validHexSecret(batchID) || len(observations) == 0 || len(observations) > 100 || loss == nil || err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid delivery batch")
	}
	record, err := s.db.ContactSensor(ctx, token, loss)
	if err != nil {
		return nil, s.transportError(err)
	}
	if record.State != "active" {
		return nil, s.transportError(store.ErrSensorState)
	}
	batch := transport.Batch{SchemaVersion: 1, BatchID: batchID, QueueLoss: *loss}
	response := &wire.SubmitResponse{SchemaVersion: transport.SensorProtocolVersion, BatchId: batchID}
	seen := make(map[string]bool, len(observations))
	latest := time.Now().Add(5 * time.Minute).UnixNano()
	for i, o := range observations {
		raw, err := transport.ObservationJSON(o)
		if err != nil || o.GetFeatureSetVersion() != contract.TrafficV3 || o.GetWindowEndNs() > latest {
			index := uint32(i)
			response.AcceptedEventIds = nil
			response.InvalidWindowIndex = &index
			return response, nil
		}
		if o.GetSensorId() != record.ID {
			return nil, status.Error(codes.PermissionDenied, "observation does not belong to sensor")
		}
		if seen[o.GetEventId()] {
			return nil, status.Error(codes.InvalidArgument, "duplicate event ID")
		}
		seen[o.GetEventId()] = true
		batch.Windows = append(batch.Windows, raw)
		response.AcceptedEventIds = append(response.AcceptedEventIds, o.GetEventId())
	}
	if err := s.db.IngestRegistered(ctx, batch, record.ID, s.modelID, s.policyVersion); err != nil {
		return nil, s.transportError(err)
	}
	return response, nil
}

func (s *service) transportError(err error) error {
	switch {
	case errors.Is(err, store.ErrSensorUnknown):
		return status.Error(codes.Unauthenticated, "invalid sensor credential")
	case errors.Is(err, store.ErrSensorState):
		return status.Error(codes.FailedPrecondition, "sensor paused")
	case errors.Is(err, store.ErrConflict):
		return status.Error(codes.Aborted, "observation identity conflict")
	default:
		s.log.Error("sensor_delivery_storage_unavailable")
		return status.Error(codes.Unavailable, "database temporarily unavailable")
	}
}
