package utils

import (
	"context"
	"time"

	zaploki "github.com/DavidMuth/zap-loki"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitLogger(cfg *config.Config) {
	// Set dynamic log level
	var zapConfig zap.Config
	if cfg.Debug {
		zapConfig = zap.NewProductionConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	} else {
		zapConfig = zap.NewProductionConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	// Log to console
	zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	zapConfig.OutputPaths = []string{"stdout"}
	zapConfig.ErrorOutputPaths = []string{"stderr"}

	var logger *zap.Logger
	var err error

	// Log to Loki
	if cfg.LogToLoki {
		loki := zaploki.New(context.Background(), zaploki.Config{
			Url:          cfg.LokiAddress,
			BatchMaxSize: 1000,
			BatchMaxWait: 10 * time.Second,
			Labels: map[string]string{
				"app":             "nfg_traffic_sensor_v0",
				"authSecret":      cfg.AuthSecret,
				"traffic_sensor ": cfg.SensorName,
			},
			Headers: map[string]string{
				"apikey": cfg.AuthSecret,
			},
		})

		logger, err = loki.WithCreateLogger(zapConfig)
		if err != nil {
			panic(err)
		}
	} else {
		// Default to standard zap logger
		logger, err = zapConfig.Build()
		if err != nil {
			panic(err)
		}
	}

	zap.ReplaceGlobals(logger)
}
