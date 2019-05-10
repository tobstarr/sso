package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/buzzfeed/sso/internal/auth"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
	"github.com/kelseyhightower/envconfig"
)

func init() {
	log.SetServiceName("sso-authenticator")
}

func main() {
	logger := log.NewLogEntry()

	opts := auth.NewOptions()

	err := envconfig.Process("", opts)
	if err != nil {
		logger.Error(err, "error loading in env vars")
		os.Exit(1)
	}

	err = opts.Validate()
	if err != nil {
		logger.Error(err, "error validating opts")
		os.Exit(1)
	}

	authMux, err := auth.NewAuthenticatorMux(opts)
	if err != nil {
		logger.Error(err, "error creating new AuthenticatorMux")
		os.Exit(1)
	}
	defer authMux.Stop()

	// we leave the message field blank, which will inherit the stdlib timeout page which is sufficient
	// and better than other naive messages we would currently place here
	timeoutHandler := http.TimeoutHandler(authMux, opts.RequestTimeout, "")

	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", opts.Port),
		ReadTimeout:  opts.TCPReadTimeout,
		WriteTimeout: opts.TCPWriteTimeout,
		Handler:      auth.NewLoggingHandler(os.Stdout, timeoutHandler, opts.RequestLogging, authenticator.StatsdClient),
	}

	logger.Fatal(s.ListenAndServe())
}
