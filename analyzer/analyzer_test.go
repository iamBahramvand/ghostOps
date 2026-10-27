package analyzer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ghostops/logparser"
)

func entry(t *testing.T, timestamp, level, service, message string) logparser.Entry {
	t.Helper()
	parsed, err := logparser.ParseLine(strings.Join([]string{timestamp, level, service, message}, " "))
	if err != nil {
		t.Fatalf("parse test entry: %v", err)
	}
	return parsed
}

func TestAnalyzerGroupsWithinWindow(t *testing.T) {
	a := New(DefaultRules())
	a.AddEntry(entry(t, "2026-10-01T10:00:00Z", "ERROR", "db-service", "SQL failed"))
	a.AddEntry(entry(t, "2026-10-01T10:05:00Z", "ERROR", "db-service", "SQL failed again"))
	a.AddEntry(entry(t, "2026-10-01T10:30:00Z", "ERROR", "db-service", "SQL failed later"))

	result := a.Result()
	if len(result.Incidents) != 2 {
		t.Fatalf("incidents = %d, want 2", len(result.Incidents))
	}
	if result.Incidents[0].Total != 2 && result.Incidents[1].Total != 2 {
		t.Fatalf("expected one frequency-2 incident: %#v", result.Incidents)
	}
}

func TestAnalyzerMergesGroupsAndTracksServices(t *testing.T) {
	a := New(DefaultRules())
	a.AddEntry(entry(t, "2026-10-01T10:00:00Z", "ERROR", "db-service", "SQL one"))
	a.AddEntry(entry(t, "2026-10-01T10:20:00Z", "ERROR", "db-service", "SQL two"))
	a.AddEntry(entry(t, "2026-10-01T10:10:00Z", "ERROR", "api-service", "SQL bridge"))

	incidents := a.Result().Incidents
	if len(incidents) != 1 || incidents[0].Total != 3 {
		t.Fatalf("incidents = %#v, want one merged group with total 3", incidents)
	}
	if len(incidents[0].Services) != 2 {
		t.Fatalf("services = %#v, want two services", incidents[0].Services)
	}
}

func TestSingletonJSONOmitsFrequencyAndRange(t *testing.T) {
	a := New(DefaultRules())
	a.AddEntry(entry(t, "2026-10-01T10:00:00Z", "ERROR", "db-service", "SQL failed"))

	data, err := json.Marshal(a.Result().Incidents[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, field := range []string{"frequency", "start_time", "end_time"} {
		if strings.Contains(text, field) {
			t.Errorf("singleton JSON contains %q: %s", field, text)
		}
	}
}

func TestTimeRangeDays(t *testing.T) {
	rangeValue := TimeRange{}
	rangeValue.extend(time.Date(2026, 10, 1, 23, 0, 0, 0, time.UTC))
	rangeValue.extend(time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC))
	if got := rangeValue.daysCovered(); got != 2 {
		t.Errorf("daysCovered() = %d, want 2", got)
	}
}

func TestAnalyzerMalformedAndFatalRule(t *testing.T) {
	a := New(DefaultRules())
	a.AddMalformed()
	a.AddEntry(entry(t, "2026-10-01T10:00:00Z", "FATAL", "api-service", "worker stopped"))
	result := a.Result()
	if result.MalformedLines != 1 || len(result.Incidents) != 1 {
		t.Fatalf("result = %#v, want one malformed line and one incident", result)
	}
	if result.Incidents[0].Type != "Fatal Error" {
		t.Fatalf("incident type = %q, want Fatal Error", result.Incidents[0].Type)
	}
}

func TestRulesMatchBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		entry logparser.Entry
		want  string
	}{
		{name: "database", entry: entry(t, "2026-10-01T10:00:00Z", "ERROR", "db-service", "connection pool exhausted"), want: "Database Connectivity"},
		{name: "payment", entry: entry(t, "2026-10-01T10:00:00Z", "ERROR", "pay-service", "payment gateway timeout"), want: "Payment Gateway Failure"},
		{name: "exception", entry: entry(t, "2026-10-01T10:00:00Z", "ERROR", "auth-service", "exception raised"), want: "Unhandled Exception"},
		{name: "resource", entry: entry(t, "2026-10-01T10:00:00Z", "WARN", "api-service", "out of memory"), want: "Resource Pressure"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := New(DefaultRules())
			a.AddEntry(tc.entry)
			if got := a.Result().Incidents[0].Type; got != tc.want {
				t.Errorf("incident type = %q, want %q", got, tc.want)
			}
		})
	}
}
