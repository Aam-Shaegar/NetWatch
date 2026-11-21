package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"netwatch.local/netwatch/internal/transport"
)

var validCredential = regexp.MustCompile(`^[0-9a-f]{64}$`)
var validSensorID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type sensorIdentity struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	Token    string `json:"credential"`
}

func readIdentity(path string) (sensorIdentity, error) {
	file, err := os.Open(path)
	if err != nil {
		return sensorIdentity{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return sensorIdentity{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return sensorIdentity{}, fmt.Errorf("identity must be a private regular file")
	}
	var value sensorIdentity
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &value) != nil || !validCredential.MatchString(value.Token) ||
		(value.ID != "" && !validSensorID.MatchString(value.ID)) || value.Endpoint == "" {
		return sensorIdentity{}, fmt.Errorf("invalid sensor identity file")
	}
	return value, nil
}

func writeIdentity(path string, identity sensorIdentity, replace bool) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("identity directory must be controlled by its owner")
	}
	temp, err := os.CreateTemp(parent, ".netwatch-identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = json.NewEncoder(temp).Encode(identity); err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if replace {
		err = os.Rename(temp.Name(), path)
	} else {
		err = os.Link(temp.Name(), path)
	}
	if err != nil {
		return err
	}
	return directory.Sync()
}

func trustedCA(path string) (string, error) {
	if path == "" {
		return os.Getenv("NETWATCH_SENSOR_CA_PEM"), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	pem, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(pem) == 0 || len(pem) > 1<<20 {
		return "", fmt.Errorf("invalid CA file")
	}
	return string(pem), nil
}

func enrollmentCode() (string, error) {
	var raw []byte
	var err error
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "One-time registration code: ")
		raw, err = term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
	} else {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 80))
	}
	code := strings.TrimSpace(string(raw))
	if err != nil || !validCredential.MatchString(code) {
		return "", fmt.Errorf("expected a 64-character registration code")
	}
	return code, nil
}

func identityCommand(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("identity", "", "private sensor identity file")
	var endpoint, ca *string
	if command == "enroll" {
		endpoint = fs.String("endpoint", "", "gRPC TLS endpoint (grpcs://host:port)")
		ca = fs.String("ca-file", "", "optional CA PEM file")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *path == "" {
		return fmt.Errorf("%s requires --identity", command)
	}
	if command != "enroll" {
		if _, err := readIdentity(*path); err != nil {
			return err
		}
		switch command {
		case "pause":
			f, err := os.OpenFile(*path+".paused", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if errors.Is(err, os.ErrExist) {
				return nil
			}
			if err != nil {
				return err
			}
			return f.Close()
		case "resume", "remove":
			if err := os.Remove(*path + ".paused"); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if command == "remove" {
				return os.Remove(*path)
			}
			return nil
		}
	}
	pem, err := trustedCA(*ca)
	if err != nil {
		return err
	}
	client, err := transport.NewGRPCClient(*endpoint, pem)
	if err != nil {
		return err
	}
	defer client.Close()
	identity, err := readIdentity(*path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return err
		}
		identity = sensorIdentity{Endpoint: *endpoint, Token: hex.EncodeToString(secret[:])}
		if err = writeIdentity(*path, identity, false); err != nil {
			return err
		}
	case err != nil:
		return err
	case identity.Endpoint != *endpoint:
		return fmt.Errorf("endpoint differs from the stored sensor identity")
	case identity.ID != "":
		return fmt.Errorf("sensor is already enrolled")
	default:
		// Recover a completed registration when the original reply was lost.
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		response, contactErr := client.Contact(call, identity.Token, nil)
		cancel()
		if contactErr == nil {
			identity.ID = response.GetSensorId()
			return finishEnrollment(*path, identity)
		}
		if status.Code(contactErr) != codes.Unauthenticated {
			return fmt.Errorf("could not check pending registration")
		}
	}
	code, err := enrollmentCode()
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := client.Enroll(call, code, identity.Token)
	if err != nil {
		return fmt.Errorf("registration failed (%s)", status.Code(err))
	}
	if response.GetSchemaVersion() != transport.SensorProtocolVersion || response.GetState() != "active" {
		return fmt.Errorf("invalid registration response")
	}
	identity.ID = response.GetSensorId()
	return finishEnrollment(*path, identity)
}

func finishEnrollment(path string, identity sensorIdentity) error {
	if !validSensorID.MatchString(identity.ID) {
		return fmt.Errorf("invalid sensor identity from analyzer")
	}
	if err := writeIdentity(path, identity, true); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, identity.ID)
	return nil
}

// superviseCapture keeps polling while paused and restarts capture on resume.
// A temporary connection failure preserves the last known state and the spool.
func superviseCapture(ctx context.Context, options deliveryOptions, identity sensorIdentity,
	run func(context.Context) error, log *eventLog) error {
	pem, err := trustedCA(*options.ca)
	if err != nil {
		return err
	}
	client, err := transport.NewGRPCClient(identity.Endpoint, pem)
	if err != nil {
		return err
	}
	defer client.Close()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	remoteState := "active"
	var stop context.CancelFunc
	var done chan error
	stopCapture := func() error {
		if done == nil {
			return nil
		}
		stop()
		err := <-done
		done = nil
		return err
	}
	defer stopCapture()
	for {
		if _, err := os.Stat(*options.identity); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return stopCapture()
			}
			return err
		}
		_, markerErr := os.Stat(*options.identity + ".paused")
		if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
			return markerErr
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		state, contactErr := client.Contact(call, identity.Token, nil)
		cancel()
		if contactErr == nil {
			if state.GetSensorId() != identity.ID {
				return fmt.Errorf("analyzer resolved a different sensor ID")
			}
			remoteState = state.GetState()
		} else if status.Code(contactErr) == codes.Unauthenticated {
			return fmt.Errorf("sensor registration is no longer authorized")
		} else if status.Code(contactErr) != codes.Unavailable && status.Code(contactErr) != codes.DeadlineExceeded && ctx.Err() == nil {
			return fmt.Errorf("sensor control status rejected")
		}
		if remoteState == "paused" || markerErr == nil {
			if done != nil {
				_ = log.Encode(map[string]any{"event": "sensor_capture_paused"})
				if err := stopCapture(); err != nil {
					return err
				}
			}
		} else if done == nil && ctx.Err() == nil {
			child, cancelCapture := context.WithCancel(ctx)
			stop = cancelCapture
			done = make(chan error, 1)
			go func(out chan<- error) {
				defer cancelCapture()
				out <- run(child)
			}(done)
		}
		select {
		case <-ctx.Done():
			return stopCapture()
		case err := <-done:
			stop()
			done = nil
			return err
		case <-tick.C:
		}
	}
}
