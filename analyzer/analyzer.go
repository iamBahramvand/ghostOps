// Package analyzer computes statistics and groups entries into incidents.
package analyzer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"ghostops/logparser"
)

// ---------- Rules ----------

// Rule decides whether an entry belongs to an incident type.
type Rule interface {
	Name() string
	Matches(e logparser.Entry) bool
}

// keywordRule: level >= minLevel AND the message contains a keyword.
type keywordRule struct {
	name     string
	minLevel logparser.Level
	keywords []string // lowercase
}

func (r keywordRule) Name() string { return r.name }

func (r keywordRule) Matches(e logparser.Entry) bool {
	if e.Level < r.minLevel {
		return false
	}
	return containsAny(strings.ToLower(e.Message), r.keywords)
}

func containsAny(text string, words []string) bool {
	for _, word := range words {
		if strings.Contains(text, word) {
			return true
		}
	}
	return false
}

// levelRule: the entry has exactly this level, whatever the message says.
type levelRule struct {
	name  string
	level logparser.Level
}

func (r levelRule) Name() string                   { return r.name }
func (r levelRule) Matches(e logparser.Entry) bool { return e.Level == r.level }

// DefaultRules returns the rules in priority order.
// When rules overlap, the FIRST matching rule wins, so the order is the
// policy: specific message rules first, the generic FATAL rule last.
func DefaultRules() []Rule {
	return []Rule{
		keywordRule{"Database Connectivity", logparser.Error, []string{"connection pool", "connect to database"}},
		keywordRule{"SQL Error", logparser.Error, []string{"sql"}},
		keywordRule{"Payment Gateway Failure", logparser.Error, []string{"payment gateway"}},
		keywordRule{"Unhandled Exception", logparser.Error, []string{"exception"}},
		keywordRule{"Resource Pressure", logparser.Warn, []string{"memory usage", "out of memory"}},
		levelRule{"Fatal Error", logparser.Fatal},
	}
}

// ---------- Result types (what the reports show) ----------

// TimeRange is the earliest and latest time seen. Log lines are not
// guaranteed to be in order, so both ends are tracked.
type TimeRange struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// daysCovered counts the calendar days from first to last, both included.
func (t TimeRange) daysCovered() int {
	if t.FirstSeen.IsZero() {
		return 0
	}
	day := 24 * time.Hour
	return int(t.LastSeen.Truncate(day).Sub(t.FirstSeen.Truncate(day))/day) + 1
}

func (t *TimeRange) extend(ts time.Time) {
	if t.FirstSeen.IsZero() || ts.Before(t.FirstSeen) {
		t.FirstSeen = ts
	}
	if ts.After(t.LastSeen) {
		t.LastSeen = ts
	}
}

// ServiceCount is one service's share of an incident.
type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
	TimeRange
}

// BusiestDay is the calendar day (UTC) with the most entries of an incident.
type BusiestDay struct {
	Date  string `json:"date"` // YYYY-MM-DD
	Count int    `json:"count"`
}

// Incident groups entries of one type AND one severity level,
// with a per-service breakdown.
type Incident struct {
	Type       string          `json:"type"`
	Severity   logparser.Level `json:"severity"`
	Total      int             `json:"total"`
	BusiestDay BusiestDay      `json:"busiest_day"`
	// AveragePerDay is total divided by the days the whole log covers.
	AveragePerDay float64 `json:"average_per_day"`
	TimeRange
	Services []ServiceCount `json:"services"`
}

// Result is everything the reporters need.
type Result struct {
	ValidEntries   int            `json:"valid_entries"`
	MalformedLines int            `json:"malformed_lines"`
	LogDays        int            `json:"log_days"` // calendar days covered by valid entries
	ByLevel        map[string]int `json:"by_level"`
	ByService      map[string]int `json:"by_service"`
	Incidents      []Incident     `json:"incidents"`
}

// ---------- Incident groups (internal, built while streaming) ----------

// groupKey says what happened and at which level.
type groupKey struct {
	typ   string
	level logparser.Level
}

// group collects the entries of one incident.
type group struct {
	total int
	TimeRange
	services map[string]*ServiceCount
	perDay   map[int]int // dayKey -> entries; size depends on days, not lines
}

func newGroup() *group {
	return &group{
		services: make(map[string]*ServiceCount),
		perDay:   make(map[int]int),
	}
}

func (g *group) add(e logparser.Entry) {
	g.total++
	g.extend(e.Timestamp)
	g.perDay[dayKey(e.Timestamp)]++
	g.serviceFor(e.Service).record(e.Timestamp)
}

// busiestDay returns the day with the most entries. On a tie the earlier
// day wins, so the result never depends on map iteration order.
func (g *group) busiestDay() BusiestDay {
	bestKey, bestCount := 0, 0
	for key, count := range g.perDay {
		if count > bestCount || (count == bestCount && key < bestKey) {
			bestKey, bestCount = key, count
		}
	}
	return BusiestDay{Date: formatDayKey(bestKey), Count: bestCount}
}

// dayKey turns a time into a small comparable number: 2026-09-25 -> 20260925.
func dayKey(ts time.Time) int {
	year, month, day := ts.Date()
	return year*10000 + int(month)*100 + day
}

func formatDayKey(key int) string {
	return fmt.Sprintf("%04d-%02d-%02d", key/10000, key/100%100, key%100)
}

// serviceFor returns the counter of a service, creating it if needed.
func (g *group) serviceFor(name string) *ServiceCount {
	sc := g.services[name]
	if sc == nil {
		sc = &ServiceCount{Service: name}
		g.services[name] = sc
	}
	return sc
}

func (s *ServiceCount) record(ts time.Time) {
	s.Count++
	s.extend(ts)
}

// ---------- Analyzer ----------

// Analyzer is fed one entry at a time. It stores only counters, so its
// memory depends on the number of services and incident types, not on
// the size of the log file.
type Analyzer struct {
	rules     []Rule
	valid     int
	malformed int
	byLevel   map[string]int
	byService map[string]int
	groups    map[groupKey]*group
	logRange  TimeRange // first and last time of all valid entries
}

func New(rules []Rule) *Analyzer {
	return &Analyzer{
		rules:     rules,
		byLevel:   newLevelCounts(),
		byService: make(map[string]int),
		groups:    make(map[groupKey]*group),
	}
}

// newLevelCounts starts every level at 0, so the report always lists all four.
func newLevelCounts() map[string]int {
	counts := make(map[string]int)
	for _, level := range logparser.AllLevels {
		counts[level.String()] = 0
	}
	return counts
}

func (a *Analyzer) AddMalformed() {
	a.malformed++
}

func (a *Analyzer) AddEntry(e logparser.Entry) {
	a.countEntry(e)
	if rule := a.firstMatch(e); rule != nil {
		a.addToIncident(rule.Name(), e)
	}
}

func (a *Analyzer) countEntry(e logparser.Entry) {
	a.valid++
	a.byLevel[e.Level.String()]++
	a.byService[e.Service]++
	a.logRange.extend(e.Timestamp)
}

// firstMatch returns the first rule that matches, or nil.
func (a *Analyzer) firstMatch(e logparser.Entry) Rule {
	for _, rule := range a.rules {
		if rule.Matches(e) {
			return rule
		}
	}
	return nil
}

func (a *Analyzer) addToIncident(typ string, e logparser.Entry) {
	a.groupFor(groupKey{typ, e.Level}).add(e)
}

// groupFor returns the group of an incident, creating it if needed.
func (a *Analyzer) groupFor(key groupKey) *group {
	g := a.groups[key]
	if g == nil {
		g = newGroup()
		a.groups[key] = g
	}
	return g
}

// Result returns a snapshot of everything counted so far.
func (a *Analyzer) Result() Result {
	days := a.logRange.daysCovered()
	return Result{
		ValidEntries:   a.valid,
		MalformedLines: a.malformed,
		LogDays:        days,
		ByLevel:        a.byLevel,
		ByService:      a.byService,
		Incidents:      a.buildIncidents(days),
	}
}

func (a *Analyzer) buildIncidents(logDays int) []Incident {
	incidents := make([]Incident, 0, len(a.groups)) // never nil: JSON gets [] not null
	for key, g := range a.groups {
		incidents = append(incidents, Incident{
			Type:      key.typ,
			Severity:  key.level,
			Total:      g.total,
			BusiestDay: g.busiestDay(),
			AveragePerDay: averagePerDay(g.total, logDays),
			TimeRange:  g.TimeRange,
			Services:   sortedServices(g.services),
		})
	}
	sortIncidents(incidents)
	return incidents
}

// averagePerDay rounds to one decimal place.
func averagePerDay(total, days int) float64 {
	if days == 0 {
		return 0
	}
	return math.Round(float64(total)/float64(days)*10) / 10
}

// sortedServices orders by count (highest first), then by name,
// so the report is always the same for the same input.
func sortedServices(services map[string]*ServiceCount) []ServiceCount {
	list := make([]ServiceCount, 0, len(services))
	for _, sc := range services {
		list = append(list, *sc)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Service < list[j].Service
	})
	return list
}

// sortIncidents orders by severity, then total, then type name.
func sortIncidents(list []Incident) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Severity != list[j].Severity {
			return list[i].Severity > list[j].Severity
		}
		if list[i].Total != list[j].Total {
			return list[i].Total > list[j].Total
		}
		return list[i].Type < list[j].Type
	})
}