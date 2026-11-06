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
	if kind != "window" && kind != "prediction" && kind != "packet" {
		return fmt.Errorf("unknown contract %q", kind)
	}
	schemaData, err := contracts.Schemas.ReadFile(kind + ".schema.json")
	if err != nil {
		return err
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	if err = compiler.AddResource("https://netwatch.local/"+kind, schemaDoc); err != nil {
		return err
	}
	schema, err := compiler.Compile("https://netwatch.local/" + kind)
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
