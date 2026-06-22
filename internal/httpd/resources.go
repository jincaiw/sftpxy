// SPDX-License-Identifier: MIT

//go:build !bundle

package httpd

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func serveStaticDir(router chi.Router, path, fsDirPath string, disableDirectoryIndex bool) {
	fileServer(router, path, http.Dir(fsDirPath), disableDirectoryIndex)
}
