package main

// version is the printcap build version. Override at build time with:
//
//	go build -ldflags "-X main.version=1.2.3"
var version = "1.0.0-dev"

func versionString() string { return "printcap " + version }
