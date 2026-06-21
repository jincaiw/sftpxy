// SPDX-License-Identifier: MIT

//go:build bundle

package util

import (
	"html/template"
	"os"

	"github.com/jincaiw/sftpxy/v2/internal/bundle"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
)

// FindSharedDataPath searches for the specified directory name in searchDir
// and in system-wide shared data directories.
// If name is an absolute path it is returned unmodified.
func FindSharedDataPath(name, _ string) string {
	return name
}

// LoadTemplate parses the given template paths.
// It behaves like template.Must but it writes a log before exiting.
// You can optionally provide a base template (e.g. to define some custom functions)
func LoadTemplate(base *template.Template, paths ...string) *template.Template {
	var t *template.Template
	var err error

	templateFs := bundle.GetTemplatesFs()
	if base != nil {
		base, err = base.Clone()
		if err == nil {
			t, err = base.ParseFS(templateFs, paths...)
		}
	} else {
		t, err = template.ParseFS(templateFs, paths...)
	}

	if err != nil {
		logger.ErrorToConsole("error loading required template: %v", err)
		logger.ErrorToConsole(templateLoadErrorHints)
		logger.Error(logSender, "", "error loading required template: %v", err)
		os.Exit(1)
	}
	return t
}
