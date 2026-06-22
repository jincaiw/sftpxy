// SPDX-License-Identifier: MIT

//go:build bundle

package bundle

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("+bundle")
}

//go:embed templates/*
var templatesFs embed.FS

//go:embed static/*
var staticFs embed.FS

//go:embed openapi/*
var openapiFs embed.FS

// GetTemplatesFs returns the embedded filesystem with the SFTPxy templates
func GetTemplatesFs() embed.FS {
	return templatesFs
}

// GetStaticFs return the http Filesystem with the embedded static files
func GetStaticFs() http.FileSystem {
	fsys, err := fs.Sub(staticFs, "static")
	if err != nil {
		err = fmt.Errorf("unable to get embedded filesystem for static files: %w", err)
		panic(err)
	}
	return http.FS(fsys)
}

// GetOpenAPIFs return the http Filesystem with the embedded static files
func GetOpenAPIFs() http.FileSystem {
	fsys, err := fs.Sub(openapiFs, "openapi")
	if err != nil {
		err = fmt.Errorf("unable to get embedded filesystem for OpenAPI files: %w", err)
		panic(err)
	}
	return http.FS(fsys)
}
