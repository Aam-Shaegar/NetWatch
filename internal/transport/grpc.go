package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	wire "netwatch.local/netwatch/contracts/sensorv1"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/spool"
)

const SensorProtocolVersion = 1
const MaxGRPCMessage = 2 << 20

type GRPCClient struct {
	conn    *grpc.ClientConn
	service wire.SensorServiceClient
}

func NewGRPCClient(endpoint, trustPEM string) (*GRPCClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "grpcs" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, fmt.Errorf("gRPC endpoint must be grpcs://host:port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("gRPC endpoint must include host and port")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, fmt.Errorf("gRPC endpoint requires a valid port")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if trustPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || !roots.AppendCertsFromPEM([]byte(trustPEM)) {
			return nil, fmt.Errorf("could not load trusted CA")
		}
		tlsConfig.RootCAs = roots
	}
	conn, err := grpc.NewClient("dns:///"+u.Host, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(MaxGRPCMessage), grpc.MaxCallRecvMsgSize(64<<10)))
	if err != nil {
		return nil, fmt.Errorf("could not configure gRPC connection")
	}
	return &GRPCClient{conn: conn, service: wire.NewSensorServiceClient(conn)}, nil
}

func (c *GRPCClient) Close() error { return c.conn.Close() }

func (c *GRPCClient) Enroll(ctx context.Context, code, credential string) (*wire.ContactResponse, error) {
	return c.service.Enroll(ctx, &wire.EnrollRequest{SchemaVersion: SensorProtocolVersion, RegistrationCode: code, Credential: credential})
}

func authorization(ctx context.Context, credential string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+credential)
}

func (c *GRPCClient) Contact(ctx context.Context, credential string, loss *spool.Loss) (*wire.ContactResponse, error) {
	response, err := c.service.Contact(authorization(ctx, credential), &wire.ContactRequest{
		SchemaVersion: SensorProtocolVersion, QueueLoss: lossToWire(loss),
	})
	if err == nil && (response.GetSchemaVersion() != SensorProtocolVersion || response.GetSensorId() == "" ||
		(response.GetState() != "active" && response.GetState() != "paused")) {
		return nil, fmt.Errorf("invalid gRPC contact response")
	}
	return response, err
}

func (c *GRPCClient) submit(ctx context.Context, credential string, batch Batch) (*wire.SubmitResponse, error) {
	request := &wire.SubmitRequest{
		SchemaVersion: SensorProtocolVersion,
		BatchId:       batch.BatchID,
		Observations:  make([]*wire.Observation, 0, len(batch.Windows)),
		QueueLoss:     lossToWire(&batch.QueueLoss),
	}
	for _, raw := range batch.Windows {
		observation, err := observationToWire(raw)
		if err != nil {
			return nil, err
		}
		request.Observations = append(request.Observations, observation)
	}
	return c.service.Submit(authorization(ctx, credential), request)
}

func observationToWire(raw json.RawMessage) (*wire.Observation, error) {
	var w contract.Window
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, err
	}
	start, err := strconv.ParseInt(w.WindowStartNS, 10, 64)
	if err != nil {
		return nil, err
	}
	end, err := strconv.ParseInt(w.WindowEndNS, 10, 64)
	if err != nil {
		return nil, err
	}
	features := make(map[string]*wire.FeatureValue, len(w.Features))
	for name, value := range w.Features {
		features[name] = &wire.FeatureValue{Value: value}
	}
	return &wire.Observation{
		SchemaVersion: uint32(w.SchemaVersion), FeatureSetVersion: w.FeatureSetVersion,
		EventId: w.EventID, SensorId: w.SensorID, CaptureEpoch: w.CaptureEpoch, EntityType: w.EntityType, EntityId: w.EntityID,
		WindowStartNs: start, WindowEndNs: end, Features: features,
		Quality: &wire.Quality{Coverage: w.Quality.Coverage, CaptureDropped: w.Quality.CaptureDropped,
			LatePackets: w.Quality.LatePackets, StateEvictions: w.Quality.StateEvictions},
	}, nil
}

func ObservationJSON(o *wire.Observation) (json.RawMessage, error) {
	if o == nil || o.GetQuality() == nil {
		return nil, fmt.Errorf("missing gRPC observation or quality")
	}
	q := o.GetQuality()
	features := make(map[string]*float64, len(o.GetFeatures()))
	for name, value := range o.GetFeatures() {
		if value == nil {
			return nil, fmt.Errorf("missing protobuf feature wrapper")
		}
		features[name] = value.Value
	}
	w := contract.Window{
		SchemaVersion: int(o.GetSchemaVersion()), FeatureSetVersion: o.GetFeatureSetVersion(),
		EventID: o.GetEventId(), SensorID: o.GetSensorId(), CaptureEpoch: o.GetCaptureEpoch(),
		EntityType: o.GetEntityType(), EntityID: o.GetEntityId(),
		WindowStartNS: strconv.FormatInt(o.GetWindowStartNs(), 10), WindowEndNS: strconv.FormatInt(o.GetWindowEndNs(), 10),
		Features: features,
		Quality: contract.Quality{Coverage: q.GetCoverage(), CaptureDropped: q.CaptureDropped,
			LatePackets: q.GetLatePackets(), StateEvictions: q.GetStateEvictions()},
	}
	if strings.ContainsRune(w.EventID+w.SensorID+w.CaptureEpoch+w.EntityID, 0) {
		return nil, fmt.Errorf("invalid observation identity")
	}
	data, err := json.Marshal(w)
	if err == nil {
		err = contract.Validate("window", data)
	}
	return data, err
}

func lossToWire(loss *spool.Loss) *wire.QueueLoss {
	if loss == nil {
		return nil
	}
	return &wire.QueueLoss{
		Count: loss.Count, FirstEventId: loss.FirstEventID, LastEventId: loss.LastEventID,
		FirstWindowStartNs: loss.FirstWindowStartNS, LastWindowStartNs: loss.LastWindowStartNS,
	}
}

func LossFromWire(message *wire.QueueLoss) (*spool.Loss, error) {
	if message == nil {
		return nil, nil
	}
	loss := &spool.Loss{
		Count: message.GetCount(), FirstEventID: message.GetFirstEventId(), LastEventID: message.GetLastEventId(),
		FirstWindowStartNS: message.GetFirstWindowStartNs(), LastWindowStartNS: message.GetLastWindowStartNs(),
	}
	for _, id := range []string{loss.FirstEventID, loss.LastEventID} {
		if (loss.Count == 0) != (id == "") || len(id) > 200 || strings.ContainsRune(id, 0) {
			return nil, fmt.Errorf("invalid loss event ID")
		}
	}
	for _, stamp := range []string{loss.FirstWindowStartNS, loss.LastWindowStartNS} {
		if loss.Count == 0 && stamp == "" {
			continue
		}
		value, err := strconv.ParseInt(stamp, 10, 64)
		if loss.Count == 0 || err != nil || value < 0 || strconv.FormatInt(value, 10) != stamp {
			return nil, fmt.Errorf("invalid loss timestamp")
		}
	}
	return loss, nil
}
