// Package logging sets up the process-wide zap logger: JSON lines on stdout.
package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Setup installs the global logger and returns it. fields are added to
// every line.
func Setup(debug bool, fields ...zap.Field) *zap.Logger {
	level := zapcore.InfoLevel
	if debug {
		level = zapcore.DebugLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	cfg.Sampling = nil
	logger, err := cfg.Build(zap.Fields(fields...))
	if err != nil {
		// Only fails for invalid output paths, which are fixed above.
		panic(err)
	}
	zap.ReplaceGlobals(logger)
	return logger
}
