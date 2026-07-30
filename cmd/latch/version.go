package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
)

// Set by release builds through -ldflags. Source builds intentionally retain
// explicit development values rather than guessing from the local repository.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
	builtBy = "source"
)

type versionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	BuiltBy   string `json:"built_by"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func currentVersion() versionInfo {
	return versionInfo{
		Version:   strings.TrimSpace(version),
		Commit:    strings.TrimSpace(commit),
		BuiltAt:   strings.TrimSpace(date),
		BuiltBy:   strings.TrimSpace(builtBy),
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func versionCommand(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOutput := fs.Bool("json", false, "emit JSON build information")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "version does not accept positional arguments")
		return 64
	}
	info := currentVersion()
	if *jsonOutput {
		if err := json.NewEncoder(out).Encode(info); err != nil {
			fmt.Fprintf(errOut, "encode version: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "latch %s\ncommit: %s\nbuilt: %s by %s\ngo: %s\nplatform: %s\n",
		info.Version, info.Commit, info.BuiltAt, info.BuiltBy, info.GoVersion, info.Platform)
	return 0
}
