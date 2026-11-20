//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	batchSize     = 64
	flushInterval = time.Second
	maxPending    = 2000
	queueSize     = 1024
	dialTimeout   = 3 * time.Second
	writeTimeout  = 2 * time.Second
	drainTimeout  = 3 * time.Second
	retryDelay    = 5 * time.Second
)

type field struct {
	key string
	val any
}

type record struct {
	ts     time.Time
	fields []field
}

// eventSink queues records without ever blocking the relay: when the queue is full the record is counted and dropped.
type eventSink struct {
	cfg     config
	host    string
	queue   chan record
	seq     atomic.Uint64
	dropped atomic.Uint64
	done    chan struct{}
	once    sync.Once
}

func newEventSink(cfg config, host string) *eventSink {
	sink := &eventSink{cfg: cfg, host: host, queue: make(chan record, queueSize), done: make(chan struct{})}
	go sink.loop()
	return sink
}

func (s *eventSink) frame(direction string, meta frameMeta, size int) {
	fields := []field{
		{"event_type", "tui_frame"},
		{"direction", direction},
		{"frame_type", meta.typ},
		{"frame_version", meta.version},
		{"bytes", size},
	}
	if meta.requestID != "" {
		fields = append(fields, field{"request_id", meta.requestID})
	}
	if meta.command != "" {
		fields = append(fields, field{"command", meta.command})
	}
	if meta.hasOK {
		fields = append(fields, field{"ok", meta.ok})
	}
	s.emit(fields)
}

func (s *eventSink) lifecycle(name string, extra []field) {
	s.emit(append([]field{{"event_type", name}}, extra...))
}

func (s *eventSink) emit(fields []field) {
	base := []field{
		{"stream", "tui_events"},
		{"source", "errow"},
		{"run", s.cfg.run},
		{"host", s.host},
		{"bridge_seq", int(s.seq.Add(1))},
	}
	select {
	case s.queue <- record{ts: time.Now().UTC(), fields: append(base, fields...)}:
	default:
		s.dropped.Add(1)
	}
}

func (s *eventSink) close() {
	s.once.Do(func() { close(s.queue) })
	select {
	case <-s.done:
	case <-time.After(drainTimeout):
	}
}

func (s *eventSink) loop() {
	defer close(s.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	var (
		pending []record
		conn    net.Conn
		retryAt time.Time
		mirror  *os.File
	)
	if s.cfg.eventsFile != "" {
		mirror, _ = os.OpenFile(s.cfg.eventsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	}
	defer func() {
		if mirror != nil {
			_ = mirror.Close()
		}
		if conn != nil {
			_ = conn.Close()
		}
	}()

	accept := func(rec record) {
		if mirror != nil {
			_, _ = mirror.Write(append(encodeJSON(rec), '\n'))
		}
		pending = append(pending, rec)
	}
	backoff := func() {
		retryAt = time.Now().Add(retryDelay)
		if excess := len(pending) - maxPending; excess > 0 {
			s.dropped.Add(uint64(excess))
			pending = append(pending[:0], pending[excess:]...)
		}
	}
	flush := func(final bool) {
		if n := s.dropped.Swap(0); n > 0 {
			accept(record{ts: time.Now().UTC(), fields: []field{
				{"stream", "tui_events"}, {"source", "errow"}, {"run", s.cfg.run}, {"host", s.host},
				{"event_type", "bridge_dropped"}, {"dropped", int(n)},
			}})
		}
		if s.cfg.forwardAddr == "" {
			pending = pending[:0]
			return
		}
		if len(pending) == 0 {
			return
		}
		if conn == nil {
			if !final && time.Now().Before(retryAt) {
				backoff()
				return
			}
			dialed, err := net.DialTimeout("tcp", s.cfg.forwardAddr, dialTimeout)
			if err != nil {
				backoff()
				return
			}
			conn = dialed
		}
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := conn.Write(encodeForward(s.cfg.tag, pending)); err != nil {
			_ = conn.Close()
			conn = nil
			backoff()
			return
		}
		pending = pending[:0]
	}

	for {
		select {
		case rec, open := <-s.queue:
			if !open {
				flush(true)
				return
			}
			accept(rec)
			if len(pending) >= batchSize {
				flush(false)
			}
		case <-ticker.C:
			flush(false)
		}
	}
}

func encodeJSON(rec record) []byte {
	var out bytes.Buffer
	out.WriteString(`{"@timestamp":`)
	stamp, _ := json.Marshal(rec.ts.Format(time.RFC3339Nano))
	out.Write(stamp)
	for _, f := range rec.fields {
		key, _ := json.Marshal(f.key)
		val, _ := json.Marshal(f.val)
		out.WriteByte(',')
		out.Write(key)
		out.WriteByte(':')
		out.Write(val)
	}
	out.WriteByte('}')
	return out.Bytes()
}

// encodeForward renders Fluent Forward "Forward mode": [tag, [[EventTime, record], ...]] as MessagePack.
func encodeForward(tag string, records []record) []byte {
	var out bytes.Buffer
	out.WriteByte(0x92)
	packString(&out, tag)
	packHeader(&out, len(records), 0x90, 0xdc, 0xdd)
	for _, rec := range records {
		out.WriteByte(0x92)
		out.Write([]byte{0xd7, 0x00})
		var stamp [8]byte
		binary.BigEndian.PutUint32(stamp[0:4], uint32(rec.ts.Unix()))
		binary.BigEndian.PutUint32(stamp[4:8], uint32(rec.ts.Nanosecond()))
		out.Write(stamp[:])
		packHeader(&out, len(rec.fields)+1, 0x80, 0xde, 0xdf)
		packString(&out, "@timestamp")
		packString(&out, rec.ts.Format(time.RFC3339Nano))
		for _, f := range rec.fields {
			packString(&out, f.key)
			packValue(&out, f.val)
		}
	}
	return out.Bytes()
}

// packHeader writes a MessagePack array/map header: fix form below 16 entries, else the 16/32-bit form.
func packHeader(out *bytes.Buffer, n int, fixBase, tag16, tag32 byte) {
	switch {
	case n < 16:
		out.WriteByte(fixBase | byte(n))
	case n < 1<<16:
		out.WriteByte(tag16)
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(n))
		out.Write(size[:])
	default:
		out.WriteByte(tag32)
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(n))
		out.Write(size[:])
	}
}

func packString(out *bytes.Buffer, s string) {
	n := len(s)
	switch {
	case n < 32:
		out.WriteByte(0xa0 | byte(n))
	case n < 1<<8:
		out.Write([]byte{0xd9, byte(n)})
	case n < 1<<16:
		out.WriteByte(0xda)
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(n))
		out.Write(size[:])
	default:
		out.WriteByte(0xdb)
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(n))
		out.Write(size[:])
	}
	out.WriteString(s)
}

func packValue(out *bytes.Buffer, v any) {
	switch value := v.(type) {
	case string:
		packString(out, value)
	case bool:
		if value {
			out.WriteByte(0xc3)
		} else {
			out.WriteByte(0xc2)
		}
	case int:
		packInt(out, int64(value))
	case int64:
		packInt(out, value)
	default:
		out.WriteByte(0xc0)
	}
}

func packInt(out *bytes.Buffer, n int64) {
	if n >= 0 && n < 128 {
		out.WriteByte(byte(n))
		return
	}
	out.WriteByte(0xd3)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(n))
	out.Write(raw[:])
}
