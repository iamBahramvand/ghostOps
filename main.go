// GhostOps: streaming log analysis CLI.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"ghostops/analyzer"
	"ghostops/logparser"
	"ghostops/report"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ghostops:", err)
		os.Exit(1)
	}
}

// config holds what the user asked for on the command line.
type config struct {
	logPath     string
	jsonPath    string // empty means no JSON file
	topServices int    // services per incident in the terminal report
}

// run only sequences the steps; each step lives in its own function.
// It returns the first error it meets (nil means success).
func run() error {
	cfg, err := parseArgs()
	if err != nil {
		return err
	}

	result, err := analyzeFile(cfg.logPath)
	if err != nil {
		return err
	}

	if err := printReport(result, cfg.topServices); err != nil {
		return err
	}
	if cfg.jsonPath != "" {
		return saveJSON(cfg.jsonPath, result)
	}
	return nil
}

var errUsage = errors.New("usage: ghostops [-o report.json] [-top N] <logfile>")

// parseArgs reads the command line. Flags may come before or after the file:
//
//	ghostops -o report.json file.log
//	ghostops file.log -o report.json
func parseArgs() (config, error) {
	var cfg config
	flag.StringVar(&cfg.jsonPath, "o", "", "write the report as JSON to this file")
	flag.IntVar(&cfg.topServices, "top", 3, "services listed per incident in the terminal report (0 = all)")
	flag.Parse()

	if flag.NArg() == 0 {
		return config{}, errUsage
	}
	cfg.logPath = flag.Arg(0)

	// flag.Parse stops at the file name, so read the flags written after it.
	if err := flag.CommandLine.Parse(flag.Args()[1:]); err != nil {
		return config{}, err
	}
	if flag.NArg() != 0 {
		return config{}, errUsage
	}
	if cfg.topServices < 0 {
		return config{}, errors.New("-top must be 0 or greater")
	}
	return cfg, nil
}

// analyzeFile opens and closes the file; reading is done elsewhere.
func analyzeFile(path string) (analyzer.Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return analyzer.Result{}, err
	}
	defer file.Close()

	return analyzeLines(file)
}

// analyzeLines reads one line at a time, so memory does not grow
// with the size of the input.
func analyzeLines(input io.Reader) (analyzer.Result, error) {
	a := analyzer.New(analyzer.DefaultRules())
	scanner := logparser.NewLineScanner(input)

	for scanner.Scan() {
		feedLine(a, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return analyzer.Result{}, fmt.Errorf("reading input: %w", err)
	}
	return a.Result(), nil
}

// feedLine gives one line to the analyzer: counted as valid or malformed.
func feedLine(a *analyzer.Analyzer, line string) {
	entry, err := logparser.ParseLine(line)
	if err != nil {
		a.AddMalformed()
		return
	}
	a.AddEntry(entry)
}

func printReport(result analyzer.Result, topServices int) error {
	var text report.Reporter = report.TextReporter{TopServices: topServices}
	return text.Write(os.Stdout, result)
}

func saveJSON(path string, result analyzer.Result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	return writeJSONAndClose(file, result)
}

// writeJSONAndClose makes sure a failed Close is reported too.
func writeJSONAndClose(file *os.File, result analyzer.Result) error {
	var jsonReport report.Reporter = report.JSONReporter{}
	if err := jsonReport.Write(file, result); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}