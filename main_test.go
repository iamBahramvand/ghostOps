package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ghostops/analyzer"
)

func TestAnalyzeLinesUsesReaderAndPreservesResults(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		"2026-10-01T10:00:00Z ERROR db-service SQL failed",
		"malformed",
		"2026-10-01T10:01:00Z ERROR db-service SQL failed again",
	}, "\n"))
	result, err := analyzeLines(input, 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.ValidEntries != 2 || result.MalformedLines != 1 {
		t.Fatalf("result counts = %d/%d, want 2/1", result.ValidEntries, result.MalformedLines)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].Total != 2 {
		t.Fatalf("incidents = %#v, want one frequency-2 group", result.Incidents)
	}
}

func BenchmarkAnalyzeLines(b *testing.B) {
	const line = "2026-10-01T10:00:00Z ERROR db-service SQL failed\n"
	input := strings.Repeat(line, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := analyzeLines(strings.NewReader(input), 2); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAnalyzeFileMissing(t *testing.T) {
	if _, err := analyzeFile(filepath.Join(t.TempDir(), "missing.log")); err == nil {
		t.Fatal("analyzeFile() returned nil error for a missing file")
	}
}

func TestAnalyzeLinesEmptyInput(t *testing.T) {
	result, err := analyzeLines(strings.NewReader(""), 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.ValidEntries != 0 || result.MalformedLines != 0 || len(result.Incidents) != 0 {
		t.Fatalf("empty result = %#v, want zero counts and no incidents", result)
	}
	if result.Incidents == nil {
		t.Fatal("empty incidents should be an empty slice, not nil")
	}
}

func TestAnalyzeLinesOnlyMalformed(t *testing.T) {
	input := strings.NewReader("bad line\n2026-10-01 10:00:00 ERROR db-service bad timestamp\n")
	result, err := analyzeLines(input, 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.ValidEntries != 0 || result.MalformedLines != 2 || len(result.Incidents) != 0 {
		t.Fatalf("malformed result = %#v, want 0 valid, 2 malformed, no incidents", result)
	}
}

func TestRunReturnsErrorForMissingInput(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"ghostops", filepath.Join(t.TempDir(), "missing.log")}
	if err := run(); err == nil {
		t.Fatal("run() returned nil for a missing input file")
	}
}

func TestSaveJSONAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	result := analyzer.Result{ByLevel: map[string]int{}, ByService: map[string]int{}, Incidents: []analyzer.Incident{}}
	if err := writeJSONAndClose(file, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "valid_entries") {
		t.Fatalf("JSON output = %s", data)
	}
}

func TestSaveJSONReturnsCreateError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "report.json")
	if err := saveJSON(path, analyzer.Result{}); err == nil {
		t.Fatal("saveJSON() returned nil for an invalid output path")
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    config
		wantErr bool
	}{
		{name: "flags before path", args: []string{"-o", "report.json", "-top", "5", "input.log"}, want: config{logPath: "input.log", jsonPath: "report.json", topServices: 5}},
		{name: "flags after path", args: []string{"input.log", "-top", "0", "-o", "report.json"}, want: config{logPath: "input.log", jsonPath: "report.json", topServices: 0}},
		{name: "missing path", args: nil, wantErr: true},
		{name: "multiple paths", args: []string{"one.log", "two.log"}, wantErr: true},
		{name: "negative top", args: []string{"-top", "-1", "input.log"}, wantErr: true},
		{name: "unknown flag", args: []string{"-unknown", "input.log"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseConfig(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseConfig() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("parseConfig() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
