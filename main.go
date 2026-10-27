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

type config struct {
	logPath     string
	jsonPath    string
	topServices int
}

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

func parseArgs() (config, error) {
	var cfg config
	flag.StringVar(&cfg.jsonPath, "o", "", "write the report as JSON to this file")
	flag.IntVar(&cfg.topServices, "top", 3, "services listed per incident in the terminal report (0 = all)")
	flag.Parse()

	if flag.NArg() == 0 {
		return config{}, errUsage
	}
	cfg.logPath = flag.Arg(0)

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

func analyzeFile(path string) (analyzer.Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return analyzer.Result{}, err
	}
	defer file.Close()

	return analyzeLines(file)
}

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

func writeJSONAndClose(file *os.File, result analyzer.Result) error {
	var jsonReport report.Reporter = report.JSONReporter{}
	if err := jsonReport.Write(file, result); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
