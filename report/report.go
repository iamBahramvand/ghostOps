// Package report renders an analyzer.Result in different formats.
package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"ghostops/analyzer"
	"ghostops/logparser"
)

// Reporter writes a result to w. Output must be deterministic.
type Reporter interface {
	Write(w io.Writer, res analyzer.Result) error
}

type TextReporter struct{}
type JSONReporter struct{}

func (JSONReporter) Write(w io.Writer, res analyzer.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(res) // map keys are sorted by encoding/json
}

func (TextReporter) Write(w io.Writer, res analyzer.Result) error {
	bw := bufio.NewWriter(w) // remembers the first write error

	writeSummary(bw, res)
	writeCounts(bw, "By severity:", levelNames(), res.ByLevel)
	writeCounts(bw, "By service:", sortedKeys(res.ByService), res.ByService)
	writeIncidents(bw, res.Incidents)

	return bw.Flush() // returns that error, if any
}

func writeSummary(bw *bufio.Writer, res analyzer.Result) {
	fmt.Fprintln(bw, "GhostOps Report")
	fmt.Fprintln(bw, "===============")
	fmt.Fprintf(bw, "Valid entries:   %d\n", res.ValidEntries)
	fmt.Fprintf(bw, "Malformed lines: %d\n", res.MalformedLines)
}

// writeCounts prints "name  count" lines in the order given by names.
func writeCounts(bw *bufio.Writer, title string, names []string, counts map[string]int) {
	fmt.Fprintf(bw, "\n%s\n", title)
	if len(names) == 0 {
		fmt.Fprintln(bw, "  (none)")
		return
	}
	for _, name := range names {
		fmt.Fprintf(bw, "  %-24s %d\n", name, counts[name])
	}
}

func writeIncidents(bw *bufio.Writer, incidents []analyzer.Incident) {
	fmt.Fprintf(bw, "\nIncidents (%d):\n", len(incidents))
	if len(incidents) == 0 {
		fmt.Fprintln(bw, "  (none detected)")
		return
	}
	for i, incident := range incidents {
		writeIncident(bw, i+1, incident)
	}
}

func writeIncident(bw *bufio.Writer, number int, incident analyzer.Incident) {
	fmt.Fprintf(bw, "  %d. [%s] %s\n", number, incident.Severity, incident.Type)
	fmt.Fprintf(bw, "     total: %d | from %s to %s\n", incident.Total,
		incident.FirstSeen.Format(time.RFC3339), incident.LastSeen.Format(time.RFC3339))
	fmt.Fprintln(bw, "     affected services:")
	for _, sc := range incident.Services {
		writeServiceLine(bw, sc)
	}
}

// writeServiceLine prints one service: its count and its own time range.
func writeServiceLine(bw *bufio.Writer, sc analyzer.ServiceCount) {
	fmt.Fprintf(bw, "       %-22s %4d   %s -> %s\n", sc.Service, sc.Count,
		sc.FirstSeen.Format(time.RFC3339), sc.LastSeen.Format(time.RFC3339))
}

// levelNames lists the level names from INFO to FATAL.
func levelNames() []string {
	names := make([]string, 0, len(logparser.AllLevels))
	for _, level := range logparser.AllLevels {
		names = append(names, level.String())
	}
	return names
}

// sortedKeys gives map keys in alphabetical order (Go maps have no order).
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}