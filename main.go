package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

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

	return analyzeLines(file, runtime.GOMAXPROCS(0))
}

type lineJob struct {
	sequence uint64
	text     string
}

type parsedJob struct {
	sequence uint64
	entry    logparser.Entry
	err      error
}

const pipelineBufferFactor = 2

func analyzeLines(input io.Reader, workers int) (analyzer.Result, error) {
	a := analyzer.New(analyzer.DefaultRules())
	results, scanErrors := startPipeline(input, workers)
	return collectResults(a, results, scanErrors)
}

func startPipeline(input io.Reader, workers int) (<-chan parsedJob, <-chan error) {
	bufferSize := workers * pipelineBufferFactor
	jobs := make(chan lineJob, bufferSize)
	results := make(chan parsedJob, bufferSize)
	scanErrors := make(chan error, 1)

	go produceLines(logparser.NewLineScanner(input), jobs, scanErrors)
	startParsers(workers, jobs, results)
	return results, scanErrors
}

func collectResults(a *analyzer.Analyzer, results <-chan parsedJob, scanErrors <-chan error) (analyzer.Result, error) {
	pending := make(map[uint64]parsedJob)
	var next uint64
	for result := range results {
		pending[result.sequence] = result
		next = processReadyResults(a, pending, next)
	}
	if err := <-scanErrors; err != nil {
		return analyzer.Result{}, fmt.Errorf("reading input: %w", err)
	}
	return a.Result(), nil
}

func processReadyResults(a *analyzer.Analyzer, pending map[uint64]parsedJob, next uint64) uint64 {
	for {
		ready, ok := pending[next]
		if !ok {
			return next
		}
		delete(pending, next)
		processParsedJob(a, ready)
		next++
	}
}

func produceLines(scanner *bufio.Scanner, jobs chan<- lineJob, scanErrors chan<- error) {
	defer close(jobs)
	var sequence uint64
	for scanner.Scan() {
		jobs <- lineJob{sequence: sequence, text: scanner.Text()}
		sequence++
	}
	scanErrors <- scanner.Err()
}

func startParsers(workers int, jobs <-chan lineJob, results chan<- parsedJob) {
	var group sync.WaitGroup
	group.Add(workers)
	for i := 0; i < workers; i++ {
		go parseJobs(jobs, results, &group)
	}
	go closeResults(results, &group)
}

func parseJobs(jobs <-chan lineJob, results chan<- parsedJob, group *sync.WaitGroup) {
	defer group.Done()
	for job := range jobs {
		results <- parseJob(job)
	}
}

func parseJob(job lineJob) parsedJob {
	entry, err := logparser.ParseLine(job.text)
	return parsedJob{sequence: job.sequence, entry: entry, err: err}
}

func closeResults(results chan<- parsedJob, group *sync.WaitGroup) {
	group.Wait()
	close(results)
}

func processParsedJob(a *analyzer.Analyzer, job parsedJob) {
	if job.err != nil {
		a.AddMalformed()
		return
	}
	a.AddEntry(job.entry)
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
