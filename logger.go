package ablib

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type StructuredLoggerEntry struct{}

func (l *StructuredLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	var logger *zerolog.Event

	switch {
	case status < 200:
		logger = log.Warn()
	case status < 300:
		logger = log.Info()
	case status < 400:
		logger = log.Debug()
	case status < 500:
		logger = log.Error()
	default:
		logger = log.Error()
	}
	logger.Any("resp_status", status).
		Any("resp_byte_length", bytes).
		Any("resp_elapsed_ms", float64(elapsed.Nanoseconds())/1000000.0).
		Msg("request complete")
}

func (l *StructuredLoggerEntry) Panic(v interface{}, stack []byte) {
	log.Info().
		Str("stack", string(stack)).
		Str("panic", fmt.Sprintf("%+v", v)).Send()
}

func Logger(logFormat string) {
	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
		return file + ":" + strconv.Itoa(line)
	}
	zerolog.TimestampFieldName = "time"
	zerolog.LevelFieldName = "level"
	zerolog.MessageFieldName = "msg"
	zerolog.CallerFieldName = "caller"

	log.Logger = log.With().Caller().Timestamp().Logger()

	switch logFormat {
	case "json":
		log.Logger = log.Output(os.Stderr)
	case "console":
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	}
}
