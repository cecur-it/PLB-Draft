//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

const secretMarker = "PAYLOAD-SECRET-MARKER-7f3a"

func TestMain(m *testing.M) {
	if os.Getenv("BRIDGE_TEST_CHILD") == "1" {
		os.Exit(fakeTUI())
	}
	os.Exit(m.Run())
}

// fakeTUI stands in for errow-tui.real: reads one frame from the inherited fd, answers with one, exits 7.
func fakeTUI() int {
	if os.Getenv("errow_TUI_FD") != "3" || os.Getenv("errow_TUI_ADDR") != "" || os.Getenv("errow_TUI_TOKEN") != "" {
		return 90
	}
	conn, err := net.FileConn(os.NewFile(3, "fd3"))
	if err != nil {
		return 91
	}
	defer conn.Close()
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 92
	}
	body := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return 93
	}
	if _, err := conn.Write(makeFrame("command_result", "req-9", `{"ok":true,"command":"Pause","result":"`+secretMarker+`"}`)); err != nil {
		return 94
	}
	return 7
}

func makeFrame(typ, requestID, payload string) []byte {
	body := fmt.Sprintf(`{"version":3,"type":%q,"request_id":%q,"payload":%s}`, typ, requestID, payload)
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	return frame
}

func workDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".work-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func socketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var conns [2]net.Conn
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "pair")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = conn
		t.Cleanup(func() { _ = conn.Close() })
	}
	return conns[0], conns[1]
}

func TestParseMeta(t *testing.T) {
	cases := []struct {
		name string
		body string
		want frameMeta
	}{
		{"hello", `{"version":3,"type":"hello","payload":{"capabilities":["x"]}}`, frameMeta{typ: "hello", version: 3}},
		{"request id kept", `{"version":3,"type":"command","request_id":"cmd-1","payload":{"text":"` + secretMarker + `"}}`, frameMeta{typ: "command", version: 3, requestID: "cmd-1"}},
		{"command result", `{"version":3,"type":"command_result","request_id":"r","payload":{"ok":false,"command":"Stop"}}`, frameMeta{typ: "command_result", version: 3, requestID: "r", command: "stop", hasOK: true}},
		{"hostile type is neutralised", `{"version":3,"type":"x\"; DROP","request_id":"a b","payload":{}}`, frameMeta{typ: "unknown", version: 3}},
		{"not json", `not json`, frameMeta{typ: "unparseable"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseMeta([]byte(tc.body)); got != tc.want {
				t.Fatalf("parseMeta = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRelayIsTransparentAndForwardsMetadataOnly(t *testing.T) {
	dir := workDir(t)
	mirror := dir + "/events.ndjson"
	sink := newEventSink(config{eventsFile: mirror, tag: "bridge", run: "run_test"}, "unit-host")

	srcA, srcB := socketPair(t)
	dstA, dstB := socketPair(t)
	finished := make(chan struct{})
	go func() { relay("backend_to_tui", srcA, dstA, sink); close(finished) }()

	frames := [][]byte{
		makeFrame("hello", "", `{"capabilities":[]}`),
		makeFrame("command", "cmd-2", `{"text":"`+secretMarker+`"}`),
	}
	var sent []byte
	for _, frame := range frames {
		sent = append(sent, frame...)
		if _, err := srcB.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	_ = srcB.Close()
	received := make([]byte, len(sent))
	_ = dstB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(dstB, received); err != nil {
		t.Fatalf("read relayed frames: %v", err)
	}
	if !bytes.Equal(sent, received) {
		t.Fatal("relayed bytes differ from the originals")
	}
	<-finished
	if _, err := dstB.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer should observe EOF after the source closed, got %v", err)
	}
	sink.close()

	raw, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secretMarker) {
		t.Fatal("payload content leaked into the event stream")
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 events, got %d: %s", len(lines), raw)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &event); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"stream": "tui_events", "source": "errow", "run": "run_test", "host": "unit-host", "direction": "backend_to_tui",
		"frame_type": "command", "request_id": "cmd-2", "event_type": "tui_frame",
	} {
		if event[key] != want {
			t.Errorf("event[%s] = %v, want %v", key, event[key], want)
		}
	}
	if event["bytes"] != float64(len(frames[1])-4) {
		t.Errorf("bytes = %v", event["bytes"])
	}
}

func TestRelayRejectsOversizedFrames(t *testing.T) {
	srcA, srcB := socketPair(t)
	dstA, dstB := socketPair(t)
	sink := newEventSink(config{tag: "bridge"}, "h")
	defer sink.close()
	finished := make(chan struct{})
	go func() { relay("tui_to_backend", srcA, dstA, sink); close(finished) }()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxFrameBytes+1)
	_, _ = srcB.Write(header[:])
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop on an invalid frame size")
	}
	if n, _ := dstB.Read(make([]byte, 1)); n != 0 {
		t.Fatal("invalid frame must not be forwarded")
	}
}

type unpacker struct {
	data []byte
	pos  int
}

func (u *unpacker) next() any {
	b := u.data[u.pos]
	u.pos++
	read := func(n int) []byte { out := u.data[u.pos : u.pos+n]; u.pos += n; return out }
	switch {
	case b < 0x80:
		return int64(b)
	case b&0xf0 == 0x80:
		return u.mapOf(int(b & 0x0f))
	case b&0xf0 == 0x90:
		return u.arrayOf(int(b & 0x0f))
	case b&0xe0 == 0xa0:
		return string(read(int(b & 0x1f)))
	}
	switch b {
	case 0xc0:
		return nil
	case 0xc2:
		return false
	case 0xc3:
		return true
	case 0xd3:
		return int64(binary.BigEndian.Uint64(read(8)))
	case 0xd7:
		kind := read(1)[0]
		return map[string]any{"ext": int(kind), "data": read(8)}
	case 0xd9:
		return string(read(int(read(1)[0])))
	case 0xda:
		return string(read(int(binary.BigEndian.Uint16(read(2)))))
	case 0xdc:
		return u.arrayOf(int(binary.BigEndian.Uint16(read(2))))
	case 0xde:
		return u.mapOf(int(binary.BigEndian.Uint16(read(2))))
	}
	panic(fmt.Sprintf("unsupported msgpack byte 0x%x", b))
}

func (u *unpacker) arrayOf(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = u.next()
	}
	return out
}

func (u *unpacker) mapOf(n int) map[string]any {
	out := make(map[string]any, n)
	for i := 0; i < n; i++ {
		key := u.next().(string)
		out[key] = u.next()
	}
	return out
}

func TestEncodeForwardIsValidForwardMode(t *testing.T) {
	ts := time.Date(2026, 11, 12, 10, 30, 0, 123, time.UTC)
	long := strings.Repeat("x", 300)
	recs := []record{{ts: ts, fields: []field{{"event_type", "tui_frame"}, {"bytes", 70000}, {"ok", true}, {"long", long}}}}
	packet := (&unpacker{data: encodeForward("bridge", recs)}).next().([]any)
	if len(packet) != 2 || packet[0] != "bridge" {
		t.Fatalf("unexpected packet header: %v", packet[:1])
	}
	entries := packet[1].([]any)
	entry := entries[0].([]any)
	stamp := entry[0].(map[string]any)
	if stamp["ext"] != 0 {
		t.Fatalf("EventTime ext type = %v", stamp["ext"])
	}
	data := stamp["data"].([]byte)
	if binary.BigEndian.Uint32(data[:4]) != uint32(ts.Unix()) || binary.BigEndian.Uint32(data[4:]) != 123 {
		t.Fatalf("EventTime bytes = %v", data)
	}
	record := entry[1].(map[string]any)
	if record["event_type"] != "tui_frame" || record["bytes"] != int64(70000) || record["ok"] != true || record["long"] != long {
		t.Fatalf("record round trip failed: %v", record)
	}
	if record["@timestamp"] != ts.Format(time.RFC3339Nano) {
		t.Fatalf("@timestamp = %v", record["@timestamp"])
	}
}

func TestSinkDeliversToFluentBitForwardPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sink := newEventSink(config{forwardAddr: listener.Addr().String(), tag: "bridge", run: "r1"}, "h")
	sink.lifecycle("bridge_start", nil)
	sink.frame("tui_to_backend", frameMeta{typ: "ready", version: 3}, 42)
	go sink.close()

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read forward packet: %v", err)
	}
	packet := (&unpacker{data: raw}).next().([]any)
	entries := packet[1].([]any)
	if len(entries) != 2 {
		t.Fatalf("want 2 records, got %d", len(entries))
	}
	second := entries[1].([]any)[1].(map[string]any)
	if second["frame_type"] != "ready" || second["stream"] != "tui_events" || second["run"] != "r1" {
		t.Fatalf("unexpected record: %v", second)
	}
}

func TestSinkNeverBlocksWhenForwardIsDown(t *testing.T) {
	sink := newEventSink(config{forwardAddr: "127.0.0.1:1", tag: "bridge"}, "h")
	start := time.Now()
	for i := 0; i < queueSize*3; i++ {
		sink.frame("tui_to_backend", frameMeta{typ: "ping"}, 1)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("emit blocked the relay")
	}
	sink.close()
}

func TestRunBridgeRelaysThroughRealSocketpairAndPropagatesExitCode(t *testing.T) {
	dir := workDir(t)
	mirror := dir + "/events.ndjson"
	t.Setenv("BRIDGE_TEST_CHILD", "1")
	t.Setenv("errow_TUI_FD", "99")
	t.Setenv("errow_TUI_TOKEN", "must-not-reach-the-real-tui")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	upstream, backend := socketPair(t)
	cfg := config{realBin: self, tag: "bridge", eventsFile: mirror, run: "run_e2e"}

	codeCh := make(chan int, 1)
	go func() { codeCh <- runBridge(cfg, upstream) }()

	if _, err := backend.Write(makeFrame("hello", "", `{"capabilities":[]}`)); err != nil {
		t.Fatal(err)
	}
	_ = backend.SetReadDeadline(time.Now().Add(10 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(backend, header[:]); err != nil {
		t.Fatalf("no reply relayed to the backend: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(backend, body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"command_result"`) {
		t.Fatalf("unexpected reply: %s", body)
	}
	select {
	case code := <-codeCh:
		if code != 7 {
			t.Fatalf("exit code = %d, want the real TUI's 7", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("bridge did not exit with the TUI")
	}

	raw, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"direction":"backend_to_tui"`, `"direction":"tui_to_backend"`, `"command":"pause"`, `"event_type":"tui_exit","exit_code":7`, `"event_type":"bridge_start"`} {
		if !strings.Contains(text, want) {
			t.Errorf("events missing %s\n%s", want, text)
		}
	}
	if strings.Contains(text, secretMarker) {
		t.Fatal("payload content leaked into the event stream")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := workDir(t)
	real := dir + "/errow-tui.real"
	if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ERROW_TUI_REAL": real}
	cfg, err := loadConfig(nil, func(k string) string { return env[k] })
	if err != nil || cfg.forwardAddr != "fluent-bit:24225" || cfg.tag != "bridge" {
		t.Fatalf("defaults wrong: %+v %v", cfg, err)
	}
	env["ERROW_TUI_FORWARD_ADDR"] = "off"
	if cfg, _ := loadConfig(nil, func(k string) string { return env[k] }); cfg.forwardAddr != "" {
		t.Fatal("off must disable forwarding")
	}
	env["ERROW_TUI_FORWARD_ADDR"] = "no-port"
	if _, err := loadConfig(nil, func(k string) string { return env[k] }); err == nil {
		t.Fatal("address without port must be rejected")
	}
	env["ERROW_TUI_FORWARD_ADDR"] = ""
	env["ERROW_TUI_REAL"] = dir + "/missing"
	if _, err := loadConfig(nil, func(k string) string { return env[k] }); err == nil {
		t.Fatal("missing real TUI must be rejected")
	}
}
