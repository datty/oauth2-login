package main

import (
	"log"
	"log/syslog"
)

var debugLog *log.Logger
var infoLog *log.Logger
var warnLog *log.Logger
var errorLog *log.Logger

func init() {
	debugL, err := syslog.New(syslog.LOG_DEBUG, app)
	if err != nil {
		log.Fatalf("Failed to open Debug logger")
	}

	infoL, err := syslog.New(syslog.LOG_INFO, app)
	if err != nil {
		log.Fatalf("Failed to open Info logger")
	}

	warnL, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, app)
	if err != nil {
		log.Fatalf("Failed to open Warn logger")
	}

	errorL, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_ERR, app)
	if err != nil {
		log.Fatalf("Failed to open Error logger")
	}

	debugLog = log.New(debugL, "DEBUG:", log.Lshortfile)
	infoLog = log.New(infoL, "INFO:", log.Lshortfile)
	warnLog = log.New(warnL, "WARN:", log.Lshortfile)
	errorLog = log.New(errorL, "ERROR:", log.Lshortfile)
}
