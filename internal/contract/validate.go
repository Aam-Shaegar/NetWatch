package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"netwatch.local/netwatch/contracts"
)

func Validate(kind string, data []byte) error {
	kinds := []string{"window", "prediction", "packet", "batch", "ack", "rejection", "inference-request", "inference-response"}
	known := false
	for _, name := range kinds {
		if kind == name {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("unknown contract %q", kind)
	}
	compiler := jsonschema.NewCompiler()
	for _, name := range kinds {
		schemaData, err := contracts.Schemas.ReadFile(name + ".schema.json")
		if err != nil {
			return err
		}
		schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
		if err != nil {
			return err
		}
		if err = compiler.AddResource("https://netwatch.local/"+name+".schema.json", schemaDoc); err != nil {
			return err
		}
	}
	schema, err := compiler.Compile("https://netwatch.local/" + kind + ".schema.json")
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err = schema.Validate(doc); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err = dec.Decode(&obj); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	for _, key := range []string{"window_start_ns", "window_end_ns", "timestamp_ns"} {
		if raw, ok := obj[key]; ok {
			if _, err = strconv.ParseInt(raw.(string), 10, 64); err != nil {
				return fmt.Errorf("%s outside int64", key)
			}
		}
	}
	if kind == "batch" || kind == "inference-request" {
		seen := map[string]bool{}
		for _, value := range obj["windows"].([]any) {
			raw, e := json.Marshal(value)
			if e != nil {
				return e
			}
			if e = Validate("window", raw); e != nil {
				return e
			}
			id := value.(map[string]any)["event_id"].(string)
			if seen[id] {
				return fmt.Errorf("duplicate batch event_id")
			}
			seen[id] = true
		}
	}
	if kind == "inference-response" {
		seen := map[string]bool{}
		for _, value := range obj["predictions"].([]any) {
			raw, e := json.Marshal(value)
			if e != nil {
				return e
			}
			if e = Validate("prediction", raw); e != nil {
				return e
			}
			id := value.(map[string]any)["event_id"].(string)
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
		start, _ := strconv.ParseInt(obj["window_start_ns"].(string), 10, 64)
		end, _ := strconv.ParseInt(obj["window_end_ns"].(string), 10, 64)
		if end <= start {
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
