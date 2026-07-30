package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/princebabou/Latch/internal/policy"
)

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func defaultConfigFromEnv() string {
	if value := strings.TrimSpace(os.Getenv("LATCH_CONFIG")); value != "" {
		return value
	}
	if fileExists(defaultConfigPath) {
		return defaultConfigPath
	}
	if runtime.GOOS == "windows" {
		if programData := strings.TrimSpace(os.Getenv("ProgramData")); programData != "" {
			systemConfig := filepath.Join(programData, "Latch", defaultConfigPath)
			if fileExists(systemConfig) {
				return systemConfig
			}
		}
	} else {
		systemConfig := filepath.Join(string(filepath.Separator), "etc", "latch", defaultConfigPath)
		if fileExists(systemConfig) {
			return systemConfig
		}
	}
	return defaultConfigPath
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// applyEnvironmentOverrides keeps container and launcher configuration
// operationally flexible without changing the policy's security semantics.
func applyEnvironmentOverrides(config policy.Config) (policy.Config, error) {
	if value := strings.TrimSpace(os.Getenv("LATCH_AUDIT_PATH")); value != "" {
		config.Audit.Path = absoluteEnvironmentPath(value)
	}
	if value := strings.TrimSpace(os.Getenv("LATCH_APPROVAL_STORE")); value != "" {
		config.Approvals.StorePath = absoluteEnvironmentPath(value)
	}
	if value := strings.TrimSpace(os.Getenv("LATCH_BUDGET_STORE")); value != "" {
		config.Budgets.StorePath = absoluteEnvironmentPath(value)
	}
	if value := strings.TrimSpace(os.Getenv("LATCH_AUDIT_TERMINAL")); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return policy.Config{}, fmt.Errorf("LATCH_AUDIT_TERMINAL must be true or false")
		}
		config.Audit.Terminal = enabled
	}
	if err := config.Validate(); err != nil {
		return policy.Config{}, fmt.Errorf("environment-adjusted policy is invalid: %w", err)
	}
	return config, nil
}

func absoluteEnvironmentPath(value string) string {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return value
	}
	return absolute
}
