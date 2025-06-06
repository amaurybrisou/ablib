package ablib

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func LookupEnv(e, d string) (r string) {
	r = os.Getenv(e)
	if r == "" {
		return d
	}
	return r
}

func LookupEnvInt(e string, d int) (r int) {
	tr := os.Getenv(e)
	if tr == "" {
		return d
	}

	r, err := strconv.Atoi(tr)
	if err != nil {
		log.Fatal().Err(err).Msg("strconv.Atoi()")
		return -1
	}
	return r
}

func LookupEnvFloat64(e string, d float64) (r float64) {
	tr := os.Getenv(e)
	if tr == "" {
		return d
	}

	r, err := strconv.ParseFloat(tr, 64)
	if err != nil {
		log.Fatal().Err(err).Msg("strconv.Atoi()")
		return -1
	}
	return r
}

func LookupEnvDuration(e string, d string) (r time.Duration) {
	tr := os.Getenv(e)
	if tr == "" && d == "" {
		log.Fatal().Err(fmt.Errorf("key %s: duration is empty", e))
	}

	if tr == "" {
		tr = d
	}

	r, err := time.ParseDuration(tr)
	if err != nil {
		log.Fatal().Err(fmt.Errorf("key %s: parsing duration", tr))
	}
	return r
}

func init() {
	file, err := os.Open(".env")
	if err != nil {
		fmt.Println("loading environment: ", err)
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close .env file")
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if err := os.Setenv(key, value); err != nil {
					fmt.Printf("{\"level\":\"error\", \"msg\":\"failed to set env variable\", \"error\":\"%s\"}\n", err)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
