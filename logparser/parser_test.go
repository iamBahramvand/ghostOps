package logparser

import "testing"

func TestParseLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
		level   Level
		service string
	}{
		{name: "valid", line: "2026-10-01T05:10:00Z ERROR order-service SQL failed", level: Error, service: "order-service"},
		{name: "carriage return", line: "2026-10-01T05:10:00Z WARN api-gateway memory high\r", level: Warn, service: "api-gateway"},
		{name: "missing fields", line: "not a log line", wantErr: true},
		{name: "bad timestamp", line: "2026-10-01 05:10:00 ERROR order-service SQL failed", wantErr: true},
		{name: "bad level", line: "2026-10-01T05:10:00Z NOTICE order-service SQL failed", wantErr: true},
		{name: "bad service", line: "2026-10-01T05:10:00Z ERROR bad_service SQL failed", wantErr: true},
		{name: "empty message", line: "2026-10-01T05:10:00Z ERROR order-service ", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := ParseLine(tc.line)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseLine() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if entry.Level != tc.level || entry.Service != tc.service {
				t.Fatalf("entry = %#v, want level %v and service %q", entry, tc.level, tc.service)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	for _, level := range Levels {
		if level.String() == "UNKNOWN" {
			t.Errorf("level %d returned UNKNOWN", level)
		}
	}
	if got := Level(-1).String(); got != "UNKNOWN" {
		t.Errorf("Level(-1).String() = %q, want UNKNOWN", got)
	}
}
