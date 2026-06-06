package encrypted

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedFileSystemRejectsPathEscape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	baseDir := filepath.Join(root, "encrypted-home")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatalf("mkdir base dir failed: %v", err)
	}

	fs, err := NewEncryptedFileSystem(Config{
		BasePath: baseDir,
		Key:      base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewEncryptedFileSystem failed: %v", err)
	}

	if _, err := fs.Create(context.Background(), "../escape.txt"); err == nil {
		t.Fatal("expected path escape to be rejected")
	}
}
