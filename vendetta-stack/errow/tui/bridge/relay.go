//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strings"
)

const maxFrameBytes = 64 << 20

type frameMeta struct {
	typ       string
	version   int
	requestID string
	command   string
	hasOK     bool
	ok        bool
}

var (
	typeToken    = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)
	requestToken = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

// relay copies length-prefixed frames (4-byte big-endian size + JSON envelope) unchanged from src to dst and reports
// metadata only. When src ends, dst's write side is closed so the peer observes EOF exactly as it would without us.
func relay(direction string, src, dst net.Conn, events *eventSink) {
	var header [4]byte
	for {
		if _, err := io.ReadFull(src, header[:]); err != nil {
			break
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > maxFrameBytes {
			events.lifecycle("frame_rejected", []field{{"direction", direction}, {"bytes", int(size)}})
			break
		}
		frame := make([]byte, 4+int(size))
		copy(frame, header[:])
		if _, err := io.ReadFull(src, frame[4:]); err != nil {
			break
		}
		if _, err := dst.Write(frame); err != nil {
			break
		}
		events.frame(direction, parseMeta(frame[4:]), int(size))
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// parseMeta extracts only the envelope type, version and request id, plus the command name and ok flag of a
// command_result. Payload bodies (instructions, findings, transcripts) are never copied.
func parseMeta(body []byte) frameMeta {
	var envelope struct {
		Version   int             `json:"version"`
		Type      string          `json:"type"`
		RequestID string          `json:"request_id"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return frameMeta{typ: "unparseable"}
	}
	meta := frameMeta{typ: "unknown", version: envelope.Version}
	if typeToken.MatchString(envelope.Type) {
		meta.typ = envelope.Type
	}
	if requestToken.MatchString(envelope.RequestID) {
		meta.requestID = envelope.RequestID
	}
	if meta.typ == "command_result" {
		var result struct {
			OK      *bool  `json:"ok"`
			Command string `json:"command"`
		}
		if json.Unmarshal(envelope.Payload, &result) == nil {
			if result.OK != nil {
				meta.hasOK, meta.ok = true, *result.OK
			}
			if typeToken.MatchString(strings.ToLower(result.Command)) {
				meta.command = strings.ToLower(result.Command)
			}
		}
	}
	return meta
}
