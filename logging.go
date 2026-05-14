package main

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
)

func setupLogging() error {
	if logOutput != "syslog" {
		logWriter = os.Stderr
		return nil
	}

	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_NOTICE, "apacheblock")
	if err != nil {
		return fmt.Errorf("failed to connect to syslog: %w", err)
	}

	logWriter = w
	log.SetOutput(w)
	log.SetFlags(0)

	log.Println("apacheblock started (logging to syslog)")
	return nil
}
