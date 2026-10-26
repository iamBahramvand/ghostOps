// Package report renders an analyzer.Result in different formats.
package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"ghostops/analyzer"
	"ghostops/logparser"
)

// lineWidth is the width of the separator lines in the text report.
const lineWidth = 78

// Reporter writes a result to w. Output must be deterministic.
type Reporter interface {
	Write(w io.Writer, res analyzer.Result) error
}

// TextReporter prints a report for people reading a terminal.
type TextReporter struct {
	TopServices int // services listed per incident; 0 means all of them
}

// JSONReporter writes the complete result as JSON (never shortened).
type JSONReporter struct{}

func (JSONReporter) Write(w io.Writer, res analyzer.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(res) // map keys are sorted by encoding/json
}

func (r TextReporter) Write(w io.Writer, res analyzer.Result) error {
	bw := bufio.NewWriter(w) // remembers the first write error

	writeTitle(bw)
	writeEntries(bw, res)
	writeCounts(bw, "By severity", levelNames(), res.ByLevel, res.ValidEntries)
	writeCounts(bw, "By service", sortedKeys(res.ByService), res.ByService, res.ValidEntries)
	r.writeIncidents(bw, res.Incidents)

	return bw.Flush() // returns that error, if any
}

func writeTitle(bw *bufio.Writer) {
	fmt.Fprintln(bw, "GhostOps Report")
	fmt.Fprintln(bw, "===============")
}

func writeEntries(bw *bufio.Writer, res analyzer.Result) {
	fmt.Fprintln(bw, "\nEntries")
	fmt.Fprintf(bw, "  %-24s %7d\n", "valid", res.ValidEntries)
	fmt.Fprintf(bw, "  %-24s %7d\n", "malformed", res.MalformedLines)
	fmt.Fprintf(bw, "  %-24s %7d\n", "days covered", res.LogDays)
}

// writeCounts prints "name  count  percent" lines in the order given by names.
func writeCounts(bw *bufio.Writer, title string, names []string, counts map[string]int, total int) {
	fmt.Fprintf(bw, "\n%s\n", title)
	if len(names) == 0 {
		fmt.Fprintln(bw, "  (none)")
		return
	}
	for _, name := range names {
		fmt.Fprintf(bw, "  %-24s %7d  %5.1f%%\n", name, counts[name], percent(counts[name], total))
	}
}

func (r TextReporter) writeIncidents(bw *bufio.Writer, incidents []analyzer.Incident) {
	fmt.Fprintf(bw, "\nIncidents (%d)\n", len(incidents))
	if len(incidents) == 0 {
		fmt.Fprintln(bw, "  (none detected)")
		return
	}
	for i, incident := range incidents {
		r.writeIncident(bw, i+1, incident)
	}
}

func (r TextReporter) writeIncident(bw *bufio.Writer, number int, incident analyzer.Incident) {
	fmt.Fprintln(bw, strings.Repeat("-", lineWidth))
	fmt.Fprintf(bw, "#%d  [%s] %s\n", number, incident.Severity, incident.Type)
	fmt.Fprintf(bw, "    total: %d | busiest day: %s (%d entries, avg %.1f/day)\n",
		incident.Total, incident.BusiestDay.Date, incident.BusiestDay.Count, incident.AveragePerDay)
	fmt.Fprintf(bw, "    period: %s\n", formatRange(incident.TimeRange))
	writeServiceTable(bw, incident.Services, r.TopServices)
}

// writeServiceTable lists the most affected services and says how many
// were left out, so the numbers still add up to the incident total.
func writeServiceTable(bw *bufio.Writer, services []analyzer.ServiceCount, top int) {
	shown, hidden := splitTop(services, top)

	fmt.Fprintf(bw, "    %-22s %5s  %s\n", "service", "count", "time range")
	for _, sc := range shown {
		fmt.Fprintf(bw, "    %-22s %5d  %s\n", sc.Service, sc.Count, formatRange(sc.TimeRange))
	}
	if len(hidden) > 0 {
		fmt.Fprintf(bw, "    + %d more services (%d entries)\n", len(hidden), sumCounts(hidden))
	}
}

// splitTop splits the list after the first top items (0 keeps all).
func splitTop(services []analyzer.ServiceCount, top int) (shown, hidden []analyzer.ServiceCount) {
	if top <= 0 || top >= len(services) {
		return services, nil
	}
	return services[:top], services[top:]
}

func sumCounts(services []analyzer.ServiceCount) int {
	total := 0
	for _, sc := range services {
		total += sc.Count
	}
	return total
}

// formatRange prints one time when both ends are the same.
func formatRange(t analyzer.TimeRange) string {
	first := t.FirstSeen.Format(time.RFC3339)
	if t.FirstSeen.Equal(t.LastSeen) {
		return first
	}
	return first + " -> " + t.LastSeen.Format(time.RFC3339)
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
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