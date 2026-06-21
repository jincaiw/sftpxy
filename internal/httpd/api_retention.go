// SPDX-License-Identifier: MIT

package httpd

import (
	"net/http"

	"github.com/go-chi/render"

	"github.com/jincaiw/sftpxy/v2/internal/common"
	"github.com/jincaiw/sftpxy/v2/internal/jwt"
)

func getRetentionChecks(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	render.JSON(w, r, common.RetentionChecks.Get(claims.Role))
}
