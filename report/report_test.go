package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ghostops/analyzer"
	"ghostops/logparser"
)

func TestJSONReporterWritesValidJSON(t *testing.T) {
	result := analyzer.Result{ByLevel: map[string]int{"INFO": 1}, ByService: map[string]int{"api-service": 1}, Incidents: []analyzer.Incident{}}
	var output bytes.Buffer
	if err := (JSONReporter{}).Write(&output, result); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestTextReporterIncludesSingletonService(t *testing.T) {
	result := analyzer.Result{
		ValidEntries: 1,
		ByLevel:      map[string]int{"INFO": 1, "WARN": 0, "ERROR": 0, "FATAL": 0},
		ByService:    map[string]int{"api-service": 1},
		Incidents: []analyzer.Incident{{
			Type:     "Fatal Error",
			Severity: logparser.Fatal,
			Services: []analyzer.ServiceCount{{Service: "api-service"}},
		}},
	}
	var output bytes.Buffer
	if err := (TextReporter{}).Write(&output, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "affected service: api-service") {
		t.Fatalf("terminal report does not contain singleton service: %s", output.String())
	}
}

func TestTextReporterIncludesMultiEntryDetails(t *testing.T) {
	first := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	last := first.Add(2 * time.Minute)
	result := analyzer.Result{
		ValidEntries: 3,
		ByLevel:      map[string]int{"INFO": 0, "WARN": 0, "ERROR": 3, "FATAL": 0},
		ByService:    map[string]int{"api-service": 3, "db-service": 1},
		Incidents: []analyzer.Incident{{
			Type: "SQL Error", Severity: logparser.Error, Total: 3,
			TimeRange: analyzer.TimeRange{FirstSeen: first, LastSeen: last},
			Services: []analyzer.ServiceCount{
				{Service: "api-service", Count: 2, TimeRange: analyzer.TimeRange{FirstSeen: first, LastSeen: last}},
				{Service: "db-service", Count: 1, TimeRange: analyzer.TimeRange{FirstSeen: first, LastSeen: first}},
			},
		}},
	}
	var output bytes.Buffer
	if err := (TextReporter{TopServices: 1}).Write(&output, result); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"frequency: 3", "time:", "+ 1 more services"} {
		if !strings.Contains(text, want) {
			t.Errorf("terminal report does not contain %q", want)
		}
	}
}

func TestJSONReporterWritesRepeatedIncident(t *testing.T) {
	result := analyzer.Result{ByLevel: map[string]int{}, ByService: map[string]int{}, Incidents: []analyzer.Incident{{Type: "SQL Error", Severity: logparser.Error, Total: 2, TimeRange: analyzer.TimeRange{FirstSeen: time.Now(), LastSeen: time.Now()}, Services: []analyzer.ServiceCount{{Service: "db-service"}}}}}
	var output bytes.Buffer
	if err := (JSONReporter{}).Write(&output, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "frequency") || !strings.Contains(output.String(), "start_time") {
		t.Fatalf("repeated incident JSON = %s", output.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("writer failure")
}

func TestReportersReturnWriterErrors(t *testing.T) {
	result := analyzer.Result{ByLevel: map[string]int{}, ByService: map[string]int{}, Incidents: []analyzer.Incident{}}
	if err := (JSONReporter{}).Write(failingWriter{}, result); err == nil {
		t.Fatal("JSONReporter returned nil for a failing writer")
	}
	if err := (TextReporter{}).Write(failingWriter{}, result); err == nil {
		t.Fatal("TextReporter returned nil for a failing writer")
	}
}
