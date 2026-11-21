package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"netwatch.local/netwatch/contracts"
)

var validationSchemas = sync.OnceValues(func() (map[string]*jsonschema.Schema, error) {
	kinds := []string{"window", "prediction", "packet", "batch", "ack", "rejection", "inference-request", "inference-response", "security-observation", "security-assessment"}
	compiler := jsonschema.NewCompiler()
	for _, name := range kinds {
		schemaData, err := contracts.Schemas.ReadFile(name + ".schema.json")
		if err != nil {
			return nil, err
		}
		schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
		if err != nil {
			return nil, err
		}
		if err = compiler.AddResource("https://netwatch.local/"+name+".schema.json", schemaDoc); err != nil {
			return nil, err
		}
	}
	schemas := make(map[string]*jsonschema.Schema, len(kinds))
	for _, kind := range kinds {
		schema, err := compiler.Compile("https://netwatch.local/" + kind + ".schema.json")
		if err != nil {
			return nil, err
		}
		schemas[kind] = schema
	}
	return schemas, nil
})

func Validate(kind string, data []byte) error {
	schemas, err := validationSchemas()
	if err != nil {
		return err
	}
	schema := schemas[kind]
	if schema == nil {
		return fmt.Errorf("unknown contract %q", kind)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err = schema.Validate(doc); err != nil {
		return err
	}
	return validateFields(kind, doc.(map[string]any))
}

// Nested objects passed the enclosing schema. Apply their semantic checks
// directly to the parsed values.
func validateFields(kind string, obj map[string]any) error {
	for _, key := range []string{"window_start_ns", "window_end_ns", "timestamp_ns"} {
		if raw, ok := obj[key]; ok {
			if _, err := strconv.ParseInt(raw.(string), 10, 64); err != nil {
				return fmt.Errorf("%s outside int64", key)
			}
		}
	}
	if kind == "batch" || kind == "inference-request" {
		seen := map[string]bool{}
		for _, value := range obj["windows"].([]any) {
			record := value.(map[string]any)
			if err := validateFields("window", record); err != nil {
				return err
			}
			id := record["event_id"].(string)
			if seen[id] {
				return fmt.Errorf("duplicate batch event_id")
			}
			seen[id] = true
		}
	}
	if kind == "inference-response" {
		seen := map[string]bool{}
		for _, value := range obj["predictions"].([]any) {
			record := value.(map[string]any)
			if err := validateFields("prediction", record); err != nil {
				return err
			}
			id := record["event_id"].(string)
			if seen[id] {
				return fmt.Errorf("duplicate prediction event_id")
			}
			seen[id] = true
		}
	}
	if kind == "packet" && obj["decode_status"] == "decoded" {
		for _, field := range []string{"src_ip", "dst_ip"} {
			if net.ParseIP(obj[field].(string)) == nil {
				return fmt.Errorf("invalid IP")
			}
		}
		if obj["protocol"] == "TCP" || obj["protocol"] == "UDP" {
			if obj["src_port"] == nil || obj["dst_port"] == nil {
				return fmt.Errorf("missing transport port")
			}
		}
	}
	if kind == "window" {
		start, startErr := strconv.ParseInt(obj["window_start_ns"].(string), 10, 64)
		end, endErr := strconv.ParseInt(obj["window_end_ns"].(string), 10, 64)
		if startErr != nil || endErr != nil || end <= start {
			return fmt.Errorf("window end must exceed start")
		}
		for name, v := range obj["features"].(map[string]any) {
			if v != nil && (strings.HasSuffix(name, "packets") || strings.HasSuffix(name, "bytes") || strings.HasPrefix(name, "unique_") || strings.HasSuffix(name, "flows") || strings.HasSuffix(name, "attempts") || name == "completed_flow_count") {
				if _, e := v.(json.Number).Int64(); e != nil {
					return fmt.Errorf("%s must be int64", name)
				}
			}
		}
	}
	if kind == "prediction" {
		scored := obj["status"] == "normal" || obj["status"] == "anomalous"
		if scored != (obj["score"] != nil && obj["threshold"] != nil) {
			return fmt.Errorf("score/status mismatch")
		}
		if !scored && (obj["score"] != nil || obj["threshold"] != nil) {
			return fmt.Errorf("unavailable state has score")
		}
	}
	return nil
}
