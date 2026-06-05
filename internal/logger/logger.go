package logger

import (
	"os"
	"path/filepath"

	"github.com/jincaiw/sftpxy/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger creates a new Zap logger with JSON encoding
func NewLogger(cfg config.CommonConfig) (*zap.Logger, error) {
	// Configure encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	encoderConfig.CallerKey = "caller"
	encoderConfig.StacktraceKey = "stacktrace"

	// Set log level
	level := zapcore.InfoLevel
	switch cfg.LogLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "fatal":
		level = zapcore.FatalLevel
	}

	// Create core with console output
	consoleEncoder := zapcore.NewJSONEncoder(encoderConfig)
	consoleSyncer := zapcore.Lock(os.Stdout)
	core := zapcore.NewCore(consoleEncoder, consoleSyncer, level)

	// Add file output if configured
	if cfg.LogPath != "" {
		fileSyncer := zapcore.AddSync(&fileWriter{path: cfg.LogPath})
		fileCore := zapcore.NewCore(consoleEncoder, fileSyncer, level)
		core = zapcore.NewTee(core, fileCore)
	}

	// Create logger
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}

// fileWriter is a simple file writer
type fileWriter struct {
	path string
	file *os.File
}

func (fw *fileWriter) Write(p []byte) (n int, err error) {
	if fw.file == nil {
		dir := filepath.Dir(fw.path)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return 0, err
			}
		}
		fw.file, err = os.OpenFile(fw.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return 0, err
		}
	}
	return fw.file.Write(p)
}

func (fw *fileWriter) Sync() error {
	if fw.file != nil {
		return fw.file.Sync()
	}
	return nil
}

// HTTPMiddleware creates a middleware for logging HTTP requests
func HTTPMiddleware(logger *zap.Logger) func(next zapcore.Field) {
	return func(next zapcore.Field) {
		logger.Info("HTTP request", next)
	}
}

// WithModule creates a logger with module context
func WithModule(logger *zap.Logger, module string) *zap.Logger {
	return logger.With(zap.String("module", module))
}

// AuditLogger creates a logger for audit events
func AuditLogger(base *zap.Logger) *zap.Logger {
	return base.With(zap.String("log_type", "audit"))
}

// TransferLogger creates a logger for transfer events
func TransferLogger(base *zap.Logger) *zap.Logger {
	return base.With(zap.String("log_type", "transfer"))
}

// CommandLogger creates a logger for command events
func CommandLogger(base *zap.Logger) *zap.Logger {
	return base.With(zap.String("log_type", "command"))
}

// HTTPLogger creates a logger for HTTP events
func HTTPLogger(base *zap.Logger) *zap.Logger {
	return base.With(zap.String("log_type", "http"))
}

// DefenderLogger creates a logger for defender events
func DefenderLogger(base *zap.Logger) *zap.Logger {
	return base.With(zap.String("log_type", "defender"))
}

// EventLogger creates a logger for event manager
func EventLogger(base *zap.Logger) *zap.Logger {
	return base.With(zap.String("log_type", "event"))
}
