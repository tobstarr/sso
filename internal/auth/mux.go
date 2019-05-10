package auth

import (
	"fmt"
	"net/http"

	"github.com/buzzfeed/sso/internal/auth/providers"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/options"
)

type AuthenticatorMux struct {
	mux            *http.ServeMux
	authenticators []*Authenticator
}

func NewAuthenticatorMux(opts *Options) (*AuthenticatorMux, error) {
	logger := log.NewLogEntry()

	emailValidator := func(p *Authenticator) error {
		if len(opts.EmailAddresses) != 0 {
			p.Validator = options.NewEmailAddressValidator(opts.EmailAddresses)
		} else {
			p.Validator = options.NewEmailDomainValidator(opts.EmailDomains)
		}
		return nil
	}

	mux := http.NewServeMux()

	// one day, we will contruct more providers here
	idp, err := newProvider(opts)
	if err != nil {
		logger.Error(err, "error creating new Identity Provider")
		return nil, err
	}
	identityProviders := []providers.Provider{idp}
	authenticators := []*Authenticator{}

	for _, idp := range identityProviders {
		idpSlug := idp.Data().Slug
		authenticator, err := NewAuthenticator(opts,
			emailValidator,
			SetProvider(idp),
			SetCookieStore(opts, idpSlug),
			AssignStatsdClient(opts),
		)
		if err != nil {
			logger.Error(err, "error creating new Authenticator")
			return nil, err
		}

		authenticators = append(authenticators, authenticator)

		// we setup routes for different providers at varying URL Prefixes by their slug
		slug := fmt.Sprintf("/%s", idpSlug)
		mux.Handle(slug, http.StripPrefix(slug, authenticator.ServeMux))

		// we setup default routes for the default provider, mainly helpful for transitionary services
		if idpSlug == opts.DefaultProvider {
			mux.Handle("/", authenticator.ServeMux)
		}
	}

	return &AuthenticatorMux{
		mux:            mux,
		authenticators: authenticators,
	}, nil
}

func (a *AuthenticatorMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *AuthenticatorMux) Stop() {
	for _, authenticator := range a.authenticators {
		authenticator.Stop()
	}
}
