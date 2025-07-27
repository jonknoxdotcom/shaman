/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package main

import (
	"log/slog"
	"os"

	"github.com/jonknoxdotcom/shaman/cmd"
)

func main() {
	// init structured logging (hidden)
	logger := slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{Level: slog.LevelError},
	))
	// logger := slog.New(slog.NewJSONHandler(os.Stdout,
	// 	&slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
	slog.Info("shaman v0.0.56")

	// use cobra to run cli
	cmd.Execute()
}
