// SPDX-License-Identifier: MIT

// Package version defines SFTPxy version details
package version

import "strings"

const (
	version = "0.2.2"
	appName = "SFTPxy"
)

var (
	commit = ""
	date   = ""
	info   Info
)

var (
	config string
)

// Info defines version details
type Info struct {
	Version    string   `json:"version"`
	BuildDate  string   `json:"build_date"`
	CommitHash string   `json:"commit_hash"`
	Features   []string `json:"features"`
}

// GetAsString returns the string representation of the version
func GetAsString() string {
	var sb strings.Builder
	sb.WriteString(info.Version)
	if info.CommitHash != "" {
		sb.WriteString("-")
		sb.WriteString(info.CommitHash)
	}
	if info.BuildDate != "" {
		sb.WriteString("-")
		sb.WriteString(info.BuildDate)
	}
	if len(info.Features) > 0 {
		sb.WriteString(" ")
		sb.WriteString(strings.Join(info.Features, " "))
	}
	return sb.String()
}

func init() {
	info = Info{
		Version:    version,
		CommitHash: commit,
		BuildDate:  date,
	}
}

// AddFeature adds a feature description
func AddFeature(feature string) {
	info.Features = append(info.Features, feature)
}

// Get returns the Info struct
func Get() Info {
	return info
}

// SetConfig sets the version configuration
func SetConfig(val string) {
	config = val
}

// GetServerVersion returns the server version according to the configuration
// and the provided parameters.
func GetServerVersion(separator string, addHash bool) string {
	var sb strings.Builder
	sb.WriteString(appName)
	if config != "short" {
		sb.WriteString(separator)
		sb.WriteString(info.Version)
	}
	if addHash {
		sb.WriteString(separator)
		sb.WriteString(info.CommitHash)
	}
	return sb.String()
}

// GetVersionHash returns the server identification string with the commit hash.
func GetVersionHash() string {
	var sb strings.Builder
	sb.WriteString(appName)
	sb.WriteString("-")
	sb.WriteString(info.CommitHash)
	return sb.String()
}
