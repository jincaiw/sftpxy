package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizePathRejectsSiblingPrefixEscape(t *testing.T) {
	t.Parallel()

	baseDir := filepath.Join(t.TempDir(), "user")
	fs := NewLocalFileSystem(baseDir, true)

	if _, err := fs.sanitizePath("../user2/secret.txt"); err == nil {
		t.Fatal("expected sibling prefix escape to be rejected")
	}
}

func TestSanitizePathRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	baseDir := filepath.Join(root, "home")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatalf("mkdir base dir failed: %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("mkdir outside dir failed: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(baseDir, "escape")); err != nil {
		t.Fatalf("create symlink failed: %v", err)
	}

	fs := NewLocalFileSystem(baseDir, true)
	if _, err := fs.Open(context.Background(), "escape/secret.txt"); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}
