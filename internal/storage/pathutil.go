package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveLocalPath cleans a user-supplied path and verifies it stays within
// basePath even when existing path components are symlinks.
func ResolveLocalPath(basePath, requestedPath string) (string, error) {
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("invalid base path: %w", err)
	}
	if resolvedBase, err := filepath.EvalSymlinks(absBase); err == nil {
		absBase = resolvedBase
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("invalid base path: %w", err)
	}

	trimmedRequested := strings.TrimSpace(requestedPath)
	if trimmedRequested == "" {
		trimmedRequested = "."
	}
	trimmedRequested = strings.TrimLeft(trimmedRequested, string(filepath.Separator))
	cleanRequested := filepath.Clean(trimmedRequested)
	if cleanRequested == "." {
		cleanRequested = ""
	}
	absPath := filepath.Join(absBase, cleanRequested)

	resolvedCandidate, err := resolveExistingLocalPath(absPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	if err := ensurePathWithinBase(absBase, resolvedCandidate); err != nil {
		return "", err
	}

	return absPath, nil
}

func resolveExistingLocalPath(target string) (string, error) {
	current := target
	suffix := make([]string, 0)

	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return target, nil
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func ensurePathWithinBase(basePath, candidate string) error {
	rel, err := filepath.Rel(basePath, candidate)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("path escapes base path")
	}
	return nil
}
