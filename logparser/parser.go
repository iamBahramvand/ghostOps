// Package logparser turns raw log lines into validated entries.
package logparser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Level is a severity level, ordered from least to most severe.
type Level int

const (
	Info Level = iota
	Warn
	Error
	Fatal
)

var levelNames = [...]string{"INFO", "WARN", "ERROR", "FATAL"}

// AllLevels lists every level in ascending severity.
var AllLevels = []Level{Info, Warn, Error, Fatal}

func (l Level) String() string {
	if l < 0 || int(l) >= len(levelNames) {
		return "UNKNOWN"
	}
	return levelNames[l]
}

// MarshalText makes JSON print "ERROR" instead of 2.
func (l Level) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

// Entry is one valid log line.
type Entry struct {
	Timestamp time.Time
	Level     Level
	Service   string // e.g. "payment-service"
	Message   string
}

// rawLine holds the four pieces of a line before they are validated.
type rawLine struct {
	timestamp string
	level     string
	service   string
	message   string
}

// ParseLine converts "<time> <LEVEL> <service> <message>" into an Entry.
// An error means the line is malformed and should be skipped.
func ParseLine(line string) (Entry, error) {
	raw, err := splitLine(line)
	if err != nil {
		return Entry{}, err
	}
	return raw.toEntry()
}

// splitLine cuts a line into four pieces (the message keeps its spaces).
func splitLine(line string) (rawLine, error) {
	parts := strings.SplitN(strings.TrimSuffix(line, "\r"), " ", 4)
	if len(parts) < 4 {
		return rawLine{}, fmt.Errorf("expected 4 fields, got %d", len(parts))
	}
	return rawLine{parts[0], parts[1], parts[2], parts[3]}, nil
}

// toEntry validates every piece and builds the Entry.
func (r rawLine) toEntry() (Entry, error) {
	timestamp, err := parseTimestamp(r.timestamp)
	if err != nil {
		return Entry{}, err
	}
	level, err := parseLevel(r.level)
	if err != nil {
		return Entry{}, err
	}
	service, err := parseService(r.service)
	if err != nil {
		return Entry{}, err
	}
	message, err := parseMessage(r.message)
	if err != nil {
		return Entry{}, err
	}
	return Entry{timestamp, level, service, message}, nil
}

func parseTimestamp(text string) (time.Time, error) {
	timestamp, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q", text)
	}
	return timestamp.UTC(), nil
}

func parseLevel(text string) (Level, error) {
	for i, name := range levelNames {
		if name == text {
			return Level(i), nil
		}
	}
	return 0, fmt.Errorf("invalid level %q", text)
}

func parseService(text string) (string, error) {
	if !isValidService(text) {
		return "", fmt.Errorf("invalid service name %q", text)
	}
	return text, nil
}

func parseMessage(text string) (string, error) {
	if strings.TrimSpace(text) == "" {
		return "", errors.New("empty message")
	}
	return text, nil
}

// isValidService accepts words joined by "-" (like "auth-service").
// Any new service name works without a code change.
func isValidService(name string) bool {
	for _, word := range strings.Split(name, "-") {
		if !isLowerWord(word) {
			return false
		}
	}
	return true
}

func isLowerWord(word string) bool {
	if word == "" {
		return false
	}
	for _, ch := range word {
		isLetter := ch >= 'a' && ch <= 'z'
		isDigit := ch >= '0' && ch <= '9'
		if !isLetter && !isDigit {
			return false
		}
	}
	return true
}

// MaxLineBytes is the longest line the scanner accepts (1 MB).
const MaxLineBytes = 1 << 20

// NewLineScanner returns a scanner that reads input one line at a time.
func NewLineScanner(input io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	return scanner
}