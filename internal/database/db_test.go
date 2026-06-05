package database

import (
	"strings"
	"testing"
)

func TestAppendSQLitePragmas(t *testing.T) {
	got := appendSQLitePragmas("./data/sftpxy.db", "journal_mode(WAL)", "busy_timeout(15000)")
	if !strings.Contains(got, "?_pragma=journal_mode%28WAL%29") {
		t.Fatalf("expected first pragma query param, got %q", got)
	}
	if !strings.Contains(got, "&_pragma=busy_timeout%2815000%29") {
		t.Fatalf("expected second pragma query param, got %q", got)
	}

	withQuery := appendSQLitePragmas("file:sftpxy.db?cache=shared", "foreign_keys(ON)")
	if !strings.Contains(withQuery, "?cache=shared&_pragma=foreign_keys%28ON%29") {
		t.Fatalf("expected pragma appended with &, got %q", withQuery)
	}
}
