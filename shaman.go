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
	lvl := new(slog.LevelVar) // leveller as variable
	lvl.Set(slog.LevelError)

	logger := slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{Level: lvl},
	))
	slog.SetDefault(logger) // means can use normal log() too
	slog.Info("shaman v0.0.56")

	// use cobra to run cli
	//lvl.Set(slog.LevelDebug) // switch on debug (uncomment to enable)
	cmd.Execute()
}
