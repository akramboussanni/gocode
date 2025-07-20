package log

import (
	"log"
	"os"
)

type StdLogger struct {
	logger *log.Logger
}

func NewStdLogger() *StdLogger {
	return &StdLogger{
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (l *StdLogger) Info(args ...interface{}) {
	l.logger.SetPrefix("INFO: ")
	l.logger.Println(args...)
}

func (l *StdLogger) Warn(args ...interface{}) {
	l.logger.SetPrefix("WARN: ")
	l.logger.Println(args...)
}

func (l *StdLogger) Error(args ...interface{}) {
	l.logger.SetPrefix("ERROR: ")
	l.logger.Println(args...)
}
