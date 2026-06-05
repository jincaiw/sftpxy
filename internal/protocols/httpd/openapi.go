package httpd

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed openapi.json
var openAPISpec []byte

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	var spec map[string]any
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		s.logger.Error("load openapi spec failed")
		s.writeError(w, http.StatusInternalServerError, "OpenAPI schema is not available")
		return
	}

	if info, ok := spec["info"].(map[string]any); ok {
		info["version"] = s.version
	}
	spec["servers"] = []map[string]string{
		{"url": requestBaseURL(r)},
	}

	s.writeJSON(w, http.StatusOK, spec)
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded != "" {
		scheme = forwarded
	}

	host := strings.TrimSpace(r.Host)
	if host == "" {
		return scheme + "://localhost"
	}
	return scheme + "://" + host
}
