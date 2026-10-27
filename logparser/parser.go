package logparser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type Level int

const (
	Info Level = iota
	Warn
	Error
	Fatal
)

var levelNames = [...]string{"INFO", "WARN", "ERROR", "FATAL"}

var AllLevels = []Level{Info, Warn, Error, Fatal}

func (l Level) String() string {
	if l < 0 || int(l) >= len(levelNames) {
		return "UNKNOWN"
	}
	return levelNames[l]
}

func (l Level) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

type Entry struct {
	Timestamp time.Time
	Level     Level
	Service   string
	Message   string
}

type rawLine struct {
	timestamp string
	level     string
	service   string
	message   string
}

func ParseLine(line string) (Entry, error) {
	raw, err := splitLine(line)
	if err != nil {
		return Entry{}, err
	}
	return raw.toEntry()
}

func splitLine(line string) (rawLine, error) {
	parts := strings.SplitN(strings.TrimSuffix(line, "\r"), " ", 4)
	if len(parts) < 4 {
		return rawLine{}, fmt.Errorf("expected 4 fields, got %d", len(parts))
	}
	return rawLine{parts[0], parts[1], parts[2], parts[3]}, nil
}

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

const MaxLineBytes = 1 << 20

func NewLineScanner(input io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	return scanner
}
