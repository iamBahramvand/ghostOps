# GhostOps

GhostOps is a Go command-line tool for streaming application-log analysis. It validates each line as it is read, calculates summary statistics, detects incidents using ordered rules, and produces terminal and JSON reports without loading the complete log into memory.

## Usage

```bash
go build -o ghostops .
./ghostops example.log
./ghostops example.log -o example.json
./ghostops -top 5 example.log -o example.json
```

`-top` controls how many affected services are shown in the terminal report. Its default is 3 and `0` shows all services. The number of parser workers is selected internally from `runtime.GOMAXPROCS(0)`; the user does not need to provide a worker count.

## Requirements covered

The implementation covers the requirements from the assignment:

- Read a log-file path from the command line
- Print a human-readable terminal report
- Export a JSON report with `-o`
- Handle invalid arguments and file-operation errors
- Read input line by line with `bufio.Scanner`
- Process any `io.Reader`
- Validate RFC3339 timestamps
- Support `INFO`, `WARN`, `ERROR`, and `FATAL` levels
- Validate service names and messages
- Count valid and malformed lines
- Count entries by level and service
- Calculate the number of covered calendar days
- Detect incident patterns through configurable rules
- Resolve overlapping rules with an explicit priority order
- Group repeated incidents and calculate frequency and time range
- Produce deterministic output
- Use only the Go standard library
- Use goroutines, channels, and `sync.WaitGroup` for concurrent parsing

## Input format

Every valid line has this form:

```text
<RFC3339 timestamp> <LEVEL> <service-name> <message>
```

Example:

```text
2026-10-01T05:10:00Z ERROR order-service SQL syntax error while executing query
```

Malformed lines are skipped without stopping the analysis and are counted in `malformed_lines`.

## Incident rules

Rules are evaluated in priority order. The first matching rule wins:

| Priority | Incident | Detection condition | Group window |
|---:|---|---|---:|
| 1 | Database Connectivity | `connection pool` or `connect to database` at ERROR or above | 10 minutes |
| 2 | SQL Error | `sql` at ERROR or above | 10 minutes |
| 3 | Payment Gateway Failure | `payment gateway` at ERROR or above | 10 minutes |
| 4 | Unhandled Exception | `exception` at ERROR or above | 10 minutes |
| 5 | Resource Pressure | `memory usage` or `out of memory` at WARN or above | 15 minutes |
| 6 | Fatal Error | Any entry with level FATAL | 10 minutes |

The priority order prevents one log entry from being counted twice. For example, a FATAL entry containing SQL text is handled by the earlier SQL rule and is not counted again as a generic Fatal Error.

## Incident grouping

The base group key contains the incident type and severity. Each new matching entry is compared with the existing groups for that rule:

1. If its timestamp is inside a group’s range, or within the rule window of either endpoint, it is added to the nearest group.
2. If the new entry connects two nearby groups, those groups are merged.
3. If no group is within the rule window, a new group is created.
4. Services from the same incident are accumulated in `affected_services`.
5. The internal state also tracks a count and time range per affected service.

This approach handles logs whose timestamps are not perfectly ordered while keeping aggregate state instead of retaining every input line.

### Incident fields

For a group containing more than one entry, both reports include:

- `frequency`: the number of entries in the group
- `start_time`: the earliest timestamp
- `end_time`: the latest timestamp

For a singleton incident, `frequency`, `start_time`, and `end_time` are omitted from JSON and from the terminal report. Singletons only show their type, severity, and affected service.

## Terminal report

The terminal report contains:

- Valid and malformed entry counts
- Covered calendar days
- Level counts and percentages
- Service counts and percentages
- Detected incidents
- Frequency and time range only for multi-entry groups
- Affected services and their counts for multi-entry groups

The `-top` flag limits the service rows shown for each multi-entry incident without changing the underlying JSON report.

## JSON report

The JSON report has this general structure:

```json
{
  "valid_entries": 9990,
  "malformed_lines": 10,
  "log_days": 30,
  "by_level": {
    "ERROR": 827,
    "FATAL": 115,
    "INFO": 6537,
    "WARN": 2511
  },
  "by_service": {},
  "incidents": []
}
```

Summary fields use readable indentation. Each incident is written as a complete object on one line, keeping the JSON valid while avoiding thousands of formatting-only lines.

Repeated incident example:

```json
{"type":"SQL Error","severity":"ERROR","frequency":3,"start_time":"2026-10-01T05:10:00Z","end_time":"2026-10-01T05:10:00Z","affected_services":["order-service"]}
```

Singleton incident example:

```json
{"type":"Fatal Error","severity":"FATAL","affected_services":["api-gateway"]}
```

## Architecture

## Concurrency design

The command-line interface remains unchanged: the user provides the log path and optional reporting flags. Worker count is an implementation detail selected automatically with `runtime.GOMAXPROCS(0)`. Each pipeline channel has a small buffer sized at twice the worker count; this is queue capacity, not an additional worker count, and it lets the producer and workers absorb short bursts without loading the whole file.

The analysis pipeline has three stages:

1. A producer reads the input with `bufio.Scanner`, assigns an increasing sequence number to each line, and sends `lineJob` values through a channel.
2. Parser workers receive jobs from that channel and concurrently run `logparser.ParseLine`. Each worker sends a `parsedJob` containing the original sequence number, the parsed entry, or a validation error through a result channel.
3. The aggregator collects results, temporarily stores out-of-order results in a sequence map, and processes them only when the next sequence number is available. It then updates the analyzer in the original input order.

Channels are closed after their producers finish. A `sync.WaitGroup` waits for all parser workers before the result channel is closed. This prevents lost lines, premature shutdown, and deadlocks. The analyzer itself remains single-owner state, so grouping and deterministic report ordering do not require locks.

The concurrency lesson sample is kept in `concurrency/`.

### `logparser`

- Defines levels and their severity order
- Parses and validates one line
- Validates timestamps, levels, services, and messages
- Creates a `bufio.Scanner` with a 1 MB maximum line size

### `analyzer`

- Tracks valid and malformed counts
- Tracks level and service statistics
- Applies rules in priority order
- Maintains aggregate incident groups
- Calculates frequency and time ranges
- Sorts incidents and services deterministically

### `report`

- Defines the shared `Reporter` interface
- Renders the human-readable terminal report
- Writes valid JSON
- Applies the `-top` display limit

### `main.go`

- Parses command-line flags
- Opens and closes the input file
- Connects the reader, parser, analyzer, and reporters
- Propagates read and write errors

## Performance and memory usage

Input is scanned one line at a time. A producer sends numbered lines through a channel to parser workers. Workers validate lines concurrently and return numbered results through a second channel. The aggregator reorders results by sequence number before updating the order-sensitive analyzer, so concurrency does not change grouping or report order. Processed lines are not retained. Analyzer memory depends on the number of rules, services, aggregate incident groups, and the bounded in-flight channel window rather than the total number of physical log lines.

## Error handling

Recoverable input errors include:

- Invalid timestamps
- Unknown levels
- Invalid service names
- Empty messages
- Incomplete line structure

These lines are counted as malformed and skipped.

Execution errors include:

- Failure to open the input file
- Scanner or reader failures
- Failure to create or write the JSON file

Execution errors are returned to the caller so the program never reports false success.

## `example.log` result

Command used:

```bash
go run . example.log -o example.json
```

Current result:

- Valid entries: `9990`
- Malformed lines: `10`
- Covered days: `30`
- Incident groups: `313`
- Repeated incident groups: `240`
- JSON size: approximately `338` lines

Level counts:

| Level | Count |
|---|---:|
| INFO | 6537 |
| WARN | 2511 |
| ERROR | 827 |
| FATAL | 115 |

Incident groups by type:

| Incident type | Groups |
|---|---:|
| Fatal Error | 74 |
| SQL Error | 63 |
| Resource Pressure | 45 |
| Database Connectivity | 44 |
| Payment Gateway Failure | 44 |
| Unhandled Exception | 43 |

The generated JSON is available at [example.json](./example.json).

## Validation

The following commands complete successfully:

```bash
gofmt -w analyzer/analyzer.go logparser/parser.go report/report.go main.go
go test ./...
go vet ./...
go run . example.log -o example.json
go run -race . example.log -o example.json
```

The project demonstrates streaming input, `io.Reader` usage, parsing and validation, keyword matching, maps and slices, ordered rules, time-based grouping, goroutines, channels, `sync.WaitGroup`, deterministic aggregation, race detection, and error handling. The concurrency lesson sample is kept in `concurrency/`.

## Testing and coverage

Tests use table-driven cases and subtests across the parser, analyzer, reporters, and concurrent reader pipeline. The root package also includes a benchmark for the analysis path.

Run all tests:

```bash
go test ./...
```

Run with verbose subtest names:

```bash
go test -v ./...
```

Run the race detector:

```bash
go test -race ./...
```

Run the analyzer benchmark:

```bash
go test -bench=. -benchmem .
```

Show statement coverage per package:

```bash
go test -cover ./...
```

Create a coverage profile and inspect the combined total:

```bash
go test -coverpkg=./... -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

The last command prints a `total:` line with the overall percentage. Generate an HTML report with:

```bash
go tool cover -html=coverage.out -o coverage.html
```

For the project packages only, use this focused profile to avoid counting the teaching sample and the archived `final/` copy:

```bash
go test -coverprofile=core.out . ./analyzer ./logparser ./report
go tool cover -func=core.out
```

The current focused tests cover the main packages at approximately 83.8% for the CLI pipeline, 86.3% for the analyzer, 87.0% for the parser, and 96.4% for reporting, with a combined focused total of about 88.4%. The tests explicitly cover empty input, malformed-only input, missing files, invalid output paths, no-incident reports, and writer failures. Coverage measures executed statements; passing tests and high coverage do not replace assertions about behavior.


