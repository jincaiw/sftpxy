package version

import "testing"

func TestVersionHelpers(t *testing.T) {
	oldInfo := info
	oldConfig := config
	t.Cleanup(func() {
		info = oldInfo
		config = oldConfig
	})

	info = Info{
		Version:    "9.8.7",
		CommitHash: "deadbeef",
		BuildDate:  "2026-07-01T00:00:00Z",
	}
	config = ""

	if got := GetAsString(); got != "9.8.7-deadbeef-2026-07-01T00:00:00Z" {
		t.Fatalf("GetAsString() = %q, want %q", got, "9.8.7-deadbeef-2026-07-01T00:00:00Z")
	}
	if got := GetServerVersion("-", false); got != "SFTPxy-9.8.7" {
		t.Fatalf("GetServerVersion() = %q, want %q", got, "SFTPxy-9.8.7")
	}
	if got := GetServerVersion("-", true); got != "SFTPxy-9.8.7-deadbeef" {
		t.Fatalf("GetServerVersion(addHash) = %q, want %q", got, "SFTPxy-9.8.7-deadbeef")
	}
	SetConfig("short")
	if got := GetServerVersion("-", false); got != "SFTPxy" {
		t.Fatalf("GetServerVersion(short) = %q, want %q", got, "SFTPxy")
	}
	if got := GetVersionHash(); got != "SFTPxy-deadbeef" {
		t.Fatalf("GetVersionHash() = %q, want %q", got, "SFTPxy-deadbeef")
	}
}
