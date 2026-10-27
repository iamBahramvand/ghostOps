package analyzer

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"ghostops/logparser"
)

type Rule interface {
	Name() string
	Matches(e logparser.Entry) bool
	GroupWindow() time.Duration
}

type keywordRule struct {
	name     string
	minLevel logparser.Level
	keywords []string
	window   time.Duration
}

func (r keywordRule) Name() string               { return r.name }
func (r keywordRule) GroupWindow() time.Duration { return r.window }

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

type levelRule struct {
	name   string
	level  logparser.Level
	window time.Duration
}

func (r levelRule) Name() string                   { return r.name }
func (r levelRule) Matches(e logparser.Entry) bool { return e.Level == r.level }
func (r levelRule) GroupWindow() time.Duration     { return r.window }

func DefaultRules() []Rule {
	return []Rule{
		keywordRule{"Database Connectivity", logparser.Error, []string{"connection pool", "connect to database"}, 10 * time.Minute},
		keywordRule{"SQL Error", logparser.Error, []string{"sql"}, 10 * time.Minute},
		keywordRule{"Payment Gateway Failure", logparser.Error, []string{"payment gateway"}, 10 * time.Minute},
		keywordRule{"Unhandled Exception", logparser.Error, []string{"exception"}, 10 * time.Minute},
		keywordRule{"Resource Pressure", logparser.Warn, []string{"memory usage", "out of memory"}, 15 * time.Minute},
		levelRule{"Fatal Error", logparser.Fatal, 10 * time.Minute},
	}
}

type TimeRange struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

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

type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
	TimeRange
}

type Incident struct {
	Type     string          `json:"type"`
	Severity logparser.Level `json:"severity"`
	Total    int             `json:"total"`
	TimeRange
	Services []ServiceCount `json:"services"`
}

func (i Incident) MarshalJSON() ([]byte, error) {
	type incidentJSON struct {
		Type             string          `json:"type"`
		Severity         logparser.Level `json:"severity"`
		Frequency        *int            `json:"frequency,omitempty"`
		StartTime        *time.Time      `json:"start_time,omitempty"`
		EndTime          *time.Time      `json:"end_time,omitempty"`
		AffectedServices []string        `json:"affected_services"`
	}
	services := make([]string, 0, len(i.Services))
	for _, s := range i.Services {
		services = append(services, s.Service)
	}
	j := incidentJSON{Type: i.Type, Severity: i.Severity, AffectedServices: services}
	if i.Total > 1 {
		j.Frequency = &i.Total
		j.StartTime = &i.FirstSeen
		j.EndTime = &i.LastSeen
	}
	return json.Marshal(j)
}

type Result struct {
	ValidEntries   int            `json:"valid_entries"`
	MalformedLines int            `json:"malformed_lines"`
	LogDays        int            `json:"log_days"`
	ByLevel        map[string]int `json:"by_level"`
	ByService      map[string]int `json:"by_service"`
	Incidents      []Incident     `json:"incidents"`
}

type groupKey struct {
	typ   string
	level logparser.Level
}

type group struct {
	total     int
	lastEvent time.Time
	TimeRange
	services map[string]*ServiceCount
}

func newIncidentGroup(e logparser.Entry) *group {
	g := &group{
		services: make(map[string]*ServiceCount),
	}
	g.add(e)
	return g
}

func (g *group) add(e logparser.Entry) {
	g.total++
	g.lastEvent = e.Timestamp
	g.extend(e.Timestamp)
	g.serviceFor(e.Service).record(e.Timestamp)
}

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

type Analyzer struct {
	rules     []Rule
	valid     int
	malformed int
	byLevel   map[string]int
	byService map[string]int
	groups    map[groupKey][]*group
	logRange  TimeRange
}

func New(rules []Rule) *Analyzer {
	return &Analyzer{
		rules:     rules,
		byLevel:   newLevelCounts(),
		byService: make(map[string]int),
		groups:    make(map[groupKey][]*group),
	}
}

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
		a.addToIncident(rule, e)
	}
}

func (a *Analyzer) countEntry(e logparser.Entry) {
	a.valid++
	a.byLevel[e.Level.String()]++
	a.byService[e.Service]++
	a.logRange.extend(e.Timestamp)
}

func (a *Analyzer) firstMatch(e logparser.Entry) Rule {
	for _, rule := range a.rules {
		if rule.Matches(e) {
			return rule
		}
	}
	return nil
}

func (a *Analyzer) addToIncident(rule Rule, e logparser.Entry) {
	key := groupKey{rule.Name(), e.Level}
	groups := a.groups[key]
	matching, bestIndex := matchingGroups(groups, e.Timestamp, rule.GroupWindow())
	if bestIndex >= 0 {
		a.groups[key] = mergeMatchingGroups(groups, matching, bestIndex, e)
		return
	}
	a.groups[key] = append(groups, newIncidentGroup(e))
}

func matchingGroups(groups []*group, ts time.Time, window time.Duration) ([]int, int) {
	matching := make([]int, 0, len(groups))
	bestIndex, bestGap := -1, time.Duration(1<<63-1)
	for i, candidate := range groups {
		gap := distanceToRange(ts, candidate.TimeRange)
		if gap <= window {
			matching = append(matching, i)
			if gap < bestGap {
				bestIndex, bestGap = i, gap
			}
		}
	}
	return matching, bestIndex
}

func mergeMatchingGroups(groups []*group, matching []int, bestIndex int, e logparser.Entry) []*group {
	groups[bestIndex].add(e)
	for i := len(matching) - 1; i >= 0; i-- {
		index := matching[i]
		if index == bestIndex {
			continue
		}
		groups[bestIndex].merge(groups[index])
		groups = append(groups[:index], groups[index+1:]...)
		if index < bestIndex {
			bestIndex--
		}
	}
	return groups
}

func (g *group) merge(other *group) {
	g.total += other.total
	if other.lastEvent.After(g.lastEvent) {
		g.lastEvent = other.lastEvent
	}
	g.extend(other.FirstSeen)
	g.extend(other.LastSeen)
	for service, count := range other.services {
		target := g.serviceFor(service)
		target.Count += count.Count
		target.extend(count.FirstSeen)
		target.extend(count.LastSeen)
	}
}

func distanceToRange(ts time.Time, r TimeRange) time.Duration {
	if !ts.Before(r.FirstSeen) && !ts.After(r.LastSeen) {
		return 0
	}
	if ts.Before(r.FirstSeen) {
		return r.FirstSeen.Sub(ts)
	}
	return ts.Sub(r.LastSeen)
}

func (a *Analyzer) Result() Result {
	return Result{
		ValidEntries:   a.valid,
		MalformedLines: a.malformed,
		LogDays:        a.logRange.daysCovered(),
		ByLevel:        a.byLevel,
		ByService:      a.byService,
		Incidents:      a.buildIncidents(),
	}
}

func (a *Analyzer) buildIncidents() []Incident {
	incidents := make([]Incident, 0, len(a.groups))
	for key, groups := range a.groups {
		for _, g := range groups {
			incidents = append(incidents, Incident{
				Type:      key.typ,
				Severity:  key.level,
				Total:     g.total,
				TimeRange: g.TimeRange,
				Services:  sortedServices(g.services),
			})
		}
	}
	sortIncidents(incidents)
	return incidents
}

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

func sortIncidents(list []Incident) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Severity != list[j].Severity {
			return list[i].Severity > list[j].Severity
		}
		if list[i].Total != list[j].Total {
			return list[i].Total > list[j].Total
		}
		if list[i].Type != list[j].Type {
			return list[i].Type < list[j].Type
		}
		serviceI, serviceJ := "", ""
		if len(list[i].Services) > 0 {
			serviceI = list[i].Services[0].Service
		}
		if len(list[j].Services) > 0 {
			serviceJ = list[j].Services[0].Service
		}
		if serviceI != serviceJ {
			return serviceI < serviceJ
		}
		return list[i].FirstSeen.Before(list[j].FirstSeen)
	})
}
