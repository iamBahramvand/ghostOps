package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"ghostops/analyzer"
	"ghostops/logparser"
)

const lineWidth = 78

type Reporter interface {
	Write(w io.Writer, res analyzer.Result) error
}

type TextReporter struct {
	TopServices int
}

type JSONReporter struct{}

func (JSONReporter) Write(w io.Writer, res analyzer.Result) error {
	var b bytes.Buffer
	b.WriteString("{\n")
	writeJSONField(&b, "valid_entries", res.ValidEntries, true)
	writeJSONField(&b, "malformed_lines", res.MalformedLines, true)
	writeJSONField(&b, "log_days", res.LogDays, true)
	writeJSONField(&b, "by_level", res.ByLevel, true)
	writeJSONField(&b, "by_service", res.ByService, true)
	b.WriteString("  \"incidents\": [")
	if len(res.Incidents) > 0 {
		b.WriteByte('\n')
		for i, incident := range res.Incidents {
			data, err := json.Marshal(incident)
			if err != nil {
				return err
			}
			b.WriteString("    ")
			b.Write(data)
			if i+1 < len(res.Incidents) {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString("  ")
	}
	b.WriteString("]\n}\n")
	_, err := w.Write(b.Bytes())
	return err
}

func writeJSONField(b *bytes.Buffer, name string, value any, comma bool) {
	data, _ := json.MarshalIndent(value, "  ", "  ")
	b.WriteString("  \"")
	b.WriteString(name)
	b.WriteString("\": ")
	b.Write(data)
	if comma {
		b.WriteByte(',')
	}
	b.WriteByte('\n')
}

func (r TextReporter) Write(w io.Writer, res analyzer.Result) error {
	bw := bufio.NewWriter(w)

	writeTitle(bw)
	writeEntries(bw, res)
	writeCounts(bw, "By severity", levelNames(), res.ByLevel, res.ValidEntries)
	writeCounts(bw, "By service", sortedKeys(res.ByService), res.ByService, res.ValidEntries)
	r.writeIncidents(bw, res.Incidents)

	return bw.Flush()
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
	if incident.Total > 1 {
		fmt.Fprintf(bw, "    frequency: %d\n", incident.Total)
		fmt.Fprintf(bw, "    time range: %s\n", formatRange(incident.TimeRange))
		writeServiceTable(bw, incident.Services, r.TopServices)
		return
	}
	if len(incident.Services) > 0 {
		fmt.Fprintf(bw, "    affected service: %s\n", incident.Services[0].Service)
	}
}

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

func levelNames() []string {
	names := make([]string, 0, len(logparser.Levels))
	for _, level := range logparser.Levels {
		names = append(names, level.String())
	}
	return names
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
