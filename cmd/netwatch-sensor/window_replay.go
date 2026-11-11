package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"netwatch.local/netwatch/internal/window"
)

type windowOptions struct {
	host, service, protocol, epoch, start, end *string
	lateness                                   *time.Duration
	unique, pending                            *int
}

func windowFlags(fs *flag.FlagSet) windowOptions {
	return windowOptions{
		host:     fs.String("host", "", "aggregate windows for this host"),
		service:  fs.String("service", "", "aggregate windows for IP:port"),
		protocol: fs.String("protocol", "TCP", "service protocol"),
		epoch:    fs.String("epoch", "", "required window observation epoch"),
		start:    fs.String("coverage-start", "", "declared continuous capture start, ns"),
		end:      fs.String("coverage-end", "", "declared continuous capture end, ns (exclusive)"),
		lateness: fs.Duration("lateness", time.Second, "allowed packet lateness"),
		unique:   fs.Int("max-unique", 100000, "maximum distinct values per window"),
		pending:  fs.Int("max-pending", 100000, "maximum buffered packets"),
	}
}

func (o windowOptions) engine() (*window.Engine, error) {
	if *o.host == "" && *o.service == "" {
		return nil, nil
	}
	if *o.epoch == "" {
		return nil, fmt.Errorf("window output requires --epoch")
	}
	c := window.Config{Protocol: *o.protocol, Lateness: *o.lateness, MaxUnique: *o.unique, MaxPending: *o.pending}
	var err error
	if *o.host != "" {
		c.Host, err = netip.ParseAddr(*o.host)
		if err != nil {
			return nil, err
		}
	}
	if *o.service != "" {
		c.Service, err = netip.ParseAddrPort(*o.service)
		if err != nil {
			return nil, err
		}
	}
	for _, bound := range []struct {
		text string
		dst  **int64
	}{{*o.start, &c.CoverageStart}, {*o.end, &c.CoverageEnd}} {
		text, dst := bound.text, bound.dst
		if text != "" {
			n, e := strconv.ParseInt(text, 10, 64)
			if e != nil {
				return nil, e
			}
			*dst = &n
		}
	}
	return window.New(c)
}

func writeWindows(enc *json.Encoder, engine *window.Engine, results []window.Result, sensor, epoch string) error {
	for _, r := range results {
		w, err := engine.Export(r, sensor, epoch)
		if err != nil {
			return err
		}
		if err = enc.Encode(w); err != nil {
			return err
		}
	}
	return nil
}
