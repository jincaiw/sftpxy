// SPDX-License-Identifier: MIT

//go:build bundle

package httpd

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jincaiw/sftpxy/v2/internal/bundle"
)

func serveStaticDir(router chi.Router, path, fsDirPath string, disableDirectoryIndex bool) {
	switch path {
	case webStaticFilesPath:
		fileServer(router, path, bundle.GetStaticFs(), disableDirectoryIndex)
	case webOpenAPIPath:
		fileServer(router, path, bundle.GetOpenAPIFs(), disableDirectoryIndex)
	default:
		fileServer(router, path, http.Dir(fsDirPath), disableDirectoryIndex)
	}
}
