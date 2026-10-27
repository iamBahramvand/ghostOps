package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"ghostops/analyzer"
	"ghostops/logparser"
	"ghostops/report"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
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
	if cfg.jsonPath != "" {
		if err := rejectInputOutputCollision(cfg.logPath, cfg.jsonPath); err != nil {
			return err
		}
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
	return parseConfig(os.Args[1:])
}

func parseConfig(args []string) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("ghostops", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "usage: ghostops [-o report.json] [-top N] <logfile>")
		flags.PrintDefaults()
	}
	flags.StringVar(&cfg.jsonPath, "o", "", "write the report as JSON to this file")
	flags.IntVar(&cfg.topServices, "top", 3, "services listed per incident in the terminal report (0 = all)")
	if err := flags.Parse(reorderArgs(args)); err != nil {
		return config{}, err
	}

	if flags.NArg() == 0 {
		return config{}, errUsage
	}
	if flags.NArg() != 1 {
		return config{}, errUsage
	}
	cfg.logPath = flags.Arg(0)
	if cfg.topServices < 0 {
		return config{}, errors.New("-top must be 0 or greater")
	}
	return cfg, nil
}

func reorderArgs(args []string) []string {
	flags := make([]string, 0, len(args))
	paths := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-o" || arg == "-top" {
			flags = append(flags, arg)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			continue
		}
		paths = append(paths, arg)
	}
	return append(flags, paths...)
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
	tooLong  bool
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

	go produceLines(bufio.NewReader(input), jobs, scanErrors)
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

func produceLines(reader *bufio.Reader, jobs chan<- lineJob, scanErrors chan<- error) {
	defer close(jobs)
	var sequence uint64
	for {
		line, tooLong, err := readLine(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			scanErrors <- err
			return
		}
		jobs <- lineJob{sequence: sequence, text: line, tooLong: tooLong}
		sequence++
	}
	scanErrors <- nil
}

func readLine(reader *bufio.Reader) (string, bool, error) {
	line := make([]byte, 0, logparser.MaxLineBytes)
	tooLong := false
	for {
		fragment, isPrefix, err := reader.ReadLine()
		if len(fragment) > 0 && !tooLong {
			if len(line)+len(fragment) > logparser.MaxLineBytes {
				tooLong = true
			} else {
				line = append(line, fragment...)
			}
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				return string(line), tooLong, nil
			}
			return string(line), tooLong, err
		}
		if !isPrefix {
			return string(line), tooLong, nil
		}
	}
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
	if job.tooLong {
		return parsedJob{sequence: job.sequence, err: errors.New("line exceeds maximum size")}
	}
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

func rejectInputOutputCollision(inputPath, outputPath string) error {
	inputInfo, err := os.Stat(inputPath)
	if err != nil {
		return err
	}
	outputInfo, err := os.Stat(outputPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if os.SameFile(inputInfo, outputInfo) {
		return errors.New("input and output paths must be different files")
	}
	return nil
}

func writeJSONAndClose(file *os.File, result analyzer.Result) error {
	var jsonReport report.Reporter = report.JSONReporter{}
	if err := jsonReport.Write(file, result); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
