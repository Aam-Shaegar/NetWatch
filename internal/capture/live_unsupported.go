//go:build !linux || !cgo

package capture

import (
	"fmt"
	"io"
)

func OpenLive(iface, filter, sensor string, record io.Writer) (*LiveSource, error) {
	return nil, fmt.Errorf("live capture requires Linux with CGO and libpcap; use the sensor Docker image")
}
