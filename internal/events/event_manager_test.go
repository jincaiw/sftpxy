package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestBatchDeleteActionHandler_Execute_Basic(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	tmpDir, err := os.MkdirTemp("", "batch_delete_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldFile := filepath.Join(tmpDir, "old.txt")
	newFile := filepath.Join(tmpDir, "new.txt")
	if err := os.WriteFile(oldFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newFile, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"directory":    tmpDir,
		"max_age_days": float64(1),
		"recursive":    false,
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %v", result.Error)
	}

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("old file should have been deleted")
	}
	if _, err := os.Stat(newFile); os.IsNotExist(err) {
		t.Error("new file should still exist")
	}
}

func TestBatchDeleteActionHandler_Execute_Recursive(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	tmpDir, err := os.MkdirTemp("", "batch_delete_recursive_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	oldFile := filepath.Join(subDir, "old.txt")
	newFile := filepath.Join(subDir, "new.txt")
	if err := os.WriteFile(oldFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newFile, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	oldTime := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"directory":         tmpDir,
		"max_age_days":      float64(2),
		"recursive":         true,
		"delete_empty_dirs": false,
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %v", result.Error)
	}

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("old file in subdir should have been deleted")
	}
	if _, err := os.Stat(newFile); os.IsNotExist(err) {
		t.Error("new file in subdir should still exist")
	}
}

func TestBatchDeleteActionHandler_Execute_DeleteEmptyDirs(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	tmpDir, err := os.MkdirTemp("", "batch_delete_emptydir_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	emptyDir := filepath.Join(tmpDir, "empty_dir")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatal(err)
	}

	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(emptyDir, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"directory":         tmpDir,
		"max_age_days":      float64(1),
		"recursive":         true,
		"delete_empty_dirs": true,
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %v", result.Error)
	}

	if _, err := os.Stat(emptyDir); !os.IsNotExist(err) {
		t.Error("empty old directory should have been deleted")
	}
}

func TestBatchDeleteActionHandler_Execute_RootDirBlocked(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"directory":    "/",
		"max_age_days": float64(1),
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("root directory should be blocked")
	}
}

func TestBatchDeleteActionHandler_Execute_MaxDeletesLimit(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	tmpDir, err := os.MkdirTemp("", "batch_delete_limit_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	for i := 0; i < 5; i++ {
		f := filepath.Join(tmpDir, filepath.Join("file_"+string(rune('0'+i))+".txt"))
		if err := os.WriteFile(f, []byte("old"), 0644); err != nil {
			t.Fatal(err)
		}
		oldTime := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(f, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}
	}

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"directory":    tmpDir,
		"max_age_days": float64(1),
		"recursive":    false,
		"max_deletes":  float64(2),
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %v", result.Error)
	}

	remaining := 0
	entries, _ := os.ReadDir(tmpDir)
	for range entries {
		remaining++
	}
	if remaining < 2 {
		t.Errorf("expected at least 2 files remaining due to max_deletes limit, got %d", remaining)
	}
}

func TestBatchDeleteActionHandler_Execute_MissingDirectory(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"max_age_days": float64(1),
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("should fail when directory is missing")
	}
}

func TestBatchDeleteActionHandler_Execute_MissingMaxAgeDays(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"directory": "/tmp",
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("should fail when max_age_days is missing")
	}
}

func TestBatchDeleteActionHandler_Execute_DaysFallback(t *testing.T) {
	logger := zap.NewNop()
	handler := NewBatchDeleteActionHandler(logger)

	tmpDir, err := os.MkdirTemp("", "batch_delete_days_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	result, err := handler.Execute(context.Background(), map[string]interface{}{
		"directory": tmpDir,
		"days":      float64(1),
		"recursive": false,
	}, &EventPayload{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success with days fallback, got error: %v", result.Error)
	}
}

func TestEvaluateCondition_FileAge(t *testing.T) {
	m := NewManager(zap.NewNop(), nil)

	payload := &EventPayload{
		Extra: map[string]interface{}{
			"file_age_days": float64(30),
		},
	}

	cond := Condition{Field: "file_age", Operator: "gte", Value: float64(30)}
	if !m.evaluateCondition(cond, payload) {
		t.Error("file_age >= 30 should match when file is 30 days old")
	}

	cond = Condition{Field: "file_age", Operator: "gt", Value: float64(29)}
	if !m.evaluateCondition(cond, payload) {
		t.Error("file_age > 29 should match when file is 30 days old")
	}

	cond = Condition{Field: "file_age", Operator: "lt", Value: float64(31)}
	if !m.evaluateCondition(cond, payload) {
		t.Error("file_age < 31 should match when file is 30 days old")
	}

	cond = Condition{Field: "file_age", Operator: "eq", Value: float64(30)}
	if !m.evaluateCondition(cond, payload) {
		t.Error("file_age == 30 should match when file is 30 days old")
	}

	cond = Condition{Field: "file_age", Operator: "gte", Value: float64(31)}
	if m.evaluateCondition(cond, payload) {
		t.Error("file_age >= 31 should NOT match when file is 30 days old")
	}
}

func TestEvaluateCondition_Directory(t *testing.T) {
	m := NewManager(zap.NewNop(), nil)

	payload := &EventPayload{
		FilePath: "/data/temp",
	}

	cond := Condition{Field: "directory", Operator: "eq", Value: "/data/temp"}
	if !m.evaluateCondition(cond, payload) {
		t.Error("directory should match /data/temp")
	}

	cond = Condition{Field: "directory", Operator: "eq", Value: "/data/other"}
	if m.evaluateCondition(cond, payload) {
		t.Error("directory should NOT match /data/other")
	}
}

func TestExecuteScheduledRule_ScheduleType(t *testing.T) {
	logger := zap.NewNop()
	m := NewManager(logger, nil)

	tmpDir, err := os.MkdirTemp("", "sched_rule_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	oldFile := filepath.Join(tmpDir, "old.txt")
	if err := os.WriteFile(oldFile, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	rule := &EventRule{
		ID:          1,
		Name:        "test-schedule-batch-delete",
		TriggerType: EventSchedule,
		IsActive:    true,
		Conditions: []Condition{
			{Field: "directory", Operator: "eq", Value: tmpDir},
			{Field: "file_age", Operator: "gte", Value: float64(1)},
		},
		Actions: []ActionConfig{
			{
				Type: ActionBatchDelete,
				Config: map[string]interface{}{
					"directory":    tmpDir,
					"max_age_days": float64(1),
					"recursive":    false,
				},
			},
		},
	}
	m.AddRule(rule)

	m.executeScheduledRule(1)

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("old file should have been deleted by scheduled rule")
	}
}
