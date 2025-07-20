package log

import (
	"go.uber.org/zap"
)

type ZapLogger struct {
	logger *zap.SugaredLogger
}

func NewZapLogger() *ZapLogger {
	l, _ := zap.NewProduction()
	return &ZapLogger{logger: l.Sugar()}
}

func (l *ZapLogger) Info(args ...interface{}) {
	l.logger.Infow("", args...)
}

func (l *ZapLogger) Warn(args ...interface{}) {
	l.logger.Warnw("", args...)
}

func (l *ZapLogger) Error(args ...interface{}) {
	l.logger.Errorw("", args...)
}
