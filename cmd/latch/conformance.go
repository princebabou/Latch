package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/princebabou/Latch/internal/conformance"
)

func conformanceCommand(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("conformance", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOutput := fs.Bool("json", false, "emit the machine-readable certification report")
	manifestOutput := fs.Bool("manifest", false, "emit the embedded versioned requirement manifest")
	timeout := fs.Duration("timeout", 30*time.Second, "maximum offline suite runtime")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if *timeout <= 0 || *timeout > 5*time.Minute {
		fmt.Fprintln(errOut, "--timeout must be positive and no greater than 5m")
		return 64
	}
	if *manifestOutput {
		if *jsonOutput {
			fmt.Fprintln(errOut, "--manifest and --json are mutually exclusive")
			return 64
		}
		payload := conformance.ManifestJSON()
		_, _ = out.Write(payload)
		if len(payload) == 0 || payload[len(payload)-1] != '\n' {
			fmt.Fprintln(out)
		}
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report := conformance.Run(ctx)
	if *jsonOutput {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(report)
	} else {
		printConformanceReport(out, report)
	}
	if !report.Passed {
		return 1
	}
	return 0
}

func printConformanceReport(out io.Writer, report conformance.Report) {
	fmt.Fprintf(out, "LATCH CONFORMANCE %s (suite %s)\n\n", report.SchemaVersion, report.SuiteVersion)
	for _, adapter := range report.Adapters {
		status := "PASS"
		if !adapter.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(out, "%s  %-24s %d/%d %s checks\n", status, adapter.Name, adapter.PassedCount, adapter.PassedCount+adapter.FailedCount, adapter.Profile)
		for _, requirement := range adapter.Requirements {
			if !requirement.Passed {
				fmt.Fprintf(out, "      - %s: %s\n", requirement.ID, requirement.Message)
			}
		}
	}
	fmt.Fprintf(out, "\nResult: %d/%d passed", report.PassedCount, report.Total)
	if report.Error != "" {
		fmt.Fprintf(out, " (%s)", report.Error)
	}
	fmt.Fprintln(out)
}
