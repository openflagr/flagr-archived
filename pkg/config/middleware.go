package config

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	pem "encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/gohttp/pprof"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	negronilogrus "github.com/meatballhat/negroni-logrus"
	"github.com/phyber/negroni-gzip/gzip"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
	negroninewrelic "github.com/yadvendar/negroni-newrelic-go-agent"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

// ServerShutdown is a callback function that will be called when
// we tear down the flagr server
func ServerShutdown() {
	if Config.StatsdEnabled && Config.StatsdAPMEnabled {
		tracer.Stop()
	}
}

// SetupGlobalMiddleware setup the global middleware
func SetupGlobalMiddleware(handler http.Handler) http.Handler {
	n := negroni.New()

	if Config.MiddlewareGzipEnabled {
		n.Use(gzip.Gzip(gzip.DefaultCompression))
	}

	if Config.MiddlewareVerboseLoggerEnabled {
		middleware := negronilogrus.NewMiddlewareFromLogger(logrus.StandardLogger(), "flagr")

		for _, u := range Config.MiddlewareVerboseLoggerExcludeURLs {
			middleware.ExcludeURL(u)
		}

		n.Use(middleware)
	}

	if Config.StatsdEnabled {
		n.Use(&statsdMiddleware{StatsdClient: Global.StatsdClient})

		if Config.StatsdAPMEnabled {
			tracer.Start(
				tracer.WithAgentAddr(fmt.Sprintf("%s:%s", Config.StatsdHost, Config.StatsdAPMPort)),
				tracer.WithServiceName(Config.StatsdAPMServiceName),
			)
		}
	}

	if Config.PrometheusEnabled {
		n.Use(&prometheusMiddleware{
			counter:   Global.Prometheus.RequestCounter,
			latencies: Global.Prometheus.RequestHistogram,
		})
	}

	if Config.NewRelicEnabled {
		n.Use(&negroninewrelic.Newrelic{Application: &Global.NewrelicApp})
	}

	if Config.CORSEnabled {
		n.Use(cors.New(cors.Options{
			AllowedOrigins:   Config.CORSAllowedOrigins,
			AllowedHeaders:   Config.CORSAllowedHeaders,
			ExposedHeaders:   Config.CORSExposedHeaders,
			AllowedMethods:   Config.CORSAllowedMethods,
			AllowCredentials: Config.CORSAllowCredentials,
		}))
	}

	if Config.JWTAuthEnabled {
		n.Use(setupJWTAuthMiddleware())
	}

	if Config.BasicAuthEnabled {
		n.Use(setupBasicAuthMiddleware())
	}

	n.Use(&negroni.Static{
		Dir:       http.Dir("./browser/flagr-ui/dist/"),
		Prefix:    Config.WebPrefix,
		IndexFile: "index.html",
	})

	n.Use(setupRecoveryMiddleware())

	if Config.WebPrefix != "" {
		handler = http.StripPrefix(Config.WebPrefix, handler)
	}

	if Config.PProfEnabled {
		n.UseHandler(pprof.New()(handler))
	} else {
		n.UseHandler(handler)
	}

	return n
}

type recoveryLogger struct{}

func (r *recoveryLogger) Printf(format string, v ...interface{}) {
	logrus.Errorf(format, v...)
}

func (r *recoveryLogger) Println(v ...interface{}) {
	logrus.Errorln(v...)
}

func setupRecoveryMiddleware() *negroni.Recovery {
	r := negroni.NewRecovery()
	r.Logger = &recoveryLogger{}
	return r
}

func parseRSACertificate() (interface{}, error) {
	block, _ := pem.Decode([]byte(Config.JWTAuthSecret))
	if block == nil {
		logrus.Warnf("failed to decode PEM block containing public key")
		return nil, errors.New("failed to decode PEM")
	}

	// Parse decoded cert.
	verificationKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			verificationKey = cert.PublicKey
		} else {
			logrus.Warnf("no valid public key exists: %s\n", err)
			return nil, err
		}
	}

	return verificationKey, nil
}

/**
setupJWTAuthMiddleware setup an JWTMiddleware from the ENV config
*/
func setupJWTAuthMiddleware() *jwtAuth {
	var signingMethod jwa.SignatureAlgorithm
	var ar *jwk.AutoRefresh
	var verificationKey interface{}
	var err error

	if !Config.JWKSEnabled {
		switch Config.JWTAuthSigningMethod {
		case "HS256":
			signingMethod = jwa.HS256
			if Config.JWTAuthSecret != "" {
				verificationKey, err = jwk.New([]byte(Config.JWTAuthSecret))
			} else {
				verificationKey = nil
			}
		case "HS512":
			signingMethod = jwa.HS512
			if Config.JWTAuthSecret != "" {
				verificationKey, err = jwk.New([]byte(Config.JWTAuthSecret))
			} else {
				verificationKey = nil
			}
		case "RS256":
			signingMethod = jwa.RS256
			verificationKey, err = parseRSACertificate()
		default:
			signingMethod = jwa.HS256
			verificationKey = nil
			err = nil
		}

		if err != nil {
			logrus.Warnf("error in parsing JWTAuthSecret: %s\n", err)
		}
	} else {
		// Initialize JWKS caching.
		ar = jwk.NewAutoRefresh(context.Background())
		ar.Configure(Config.JWKSURL, jwk.WithMinRefreshInterval(Config.JWKSMinRefreshInterval))

		_, err := ar.Refresh(context.Background(), Config.JWKSURL)
		if err != nil {
			logrus.Warnf("failed to complete initial JWKS fetch successfully: %s", err)
		}
	}

	// Set options for JWT parsing.
	var JWTOptions []jwt.ParseOption
	if verificationKey != nil {
		JWTOptions = append(JWTOptions, jwt.WithVerify(signingMethod, verificationKey))
	}

	if Config.JWKSInferAlgorithmFromKey {
		JWTOptions = append(JWTOptions, jwt.InferAlgorithmFromKey(Config.JWKSInferAlgorithmFromKey))
	}

	if Config.JWKSUseDefaultKey {
		JWTOptions = append(JWTOptions, jwt.UseDefaultKey(Config.JWKSUseDefaultKey))
	}

	return &jwtAuth{
		PrefixWhitelistPaths: Config.JWTAuthPrefixWhitelistPaths,
		ExactWhitelistPaths:  Config.JWTAuthExactWhitelistPaths,
		alg:                  signingMethod,
		verifyKey:            verificationKey,
		verificationKeyErr:   err,
		userProperty:         UserPropertyType(Config.JWTAuthUserProperty),
		autoRefresh:          ar,
		parseOptions:         JWTOptions,
	}
}

func jwtErrorHandler(w http.ResponseWriter, r *http.Request) {
	switch Config.JWTAuthNoTokenStatusCode {
	case http.StatusTemporaryRedirect:
		http.Redirect(w, r, Config.JWTAuthNoTokenRedirectURL, http.StatusTemporaryRedirect)
		return
	default:
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s"`, Config.JWTAuthNoTokenRedirectURL))
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
}

// Type for userProprty value for Context.WithValue()
type UserPropertyType string

type jwtAuth struct {
	PrefixWhitelistPaths []string
	ExactWhitelistPaths  []string
	alg                  jwa.SignatureAlgorithm
	verifyKey            interface{}
	verificationKeyErr   error
	userProperty         UserPropertyType
	autoRefresh          *jwk.AutoRefresh
	parseOptions         []jwt.ParseOption
}

// Take in JWT string and parse to Token, if able.
func (a *jwtAuth) parseStringToToken(cookieValue string, params ...jwt.ParseOption) (jwt.Token, error) {
	if Config.JWKSEnabled {
		keyset, err := a.autoRefresh.Fetch(context.Background(), Config.JWKSURL)
		if err != nil {
			logrus.Warnf("failed to fetch JWKS: %s\n", err)
			return nil, err
		}

		token, err := jwt.ParseString(cookieValue, append(params, jwt.WithKeySet(keyset))...)
		return token, err
	}

	token, err := jwt.ParseString(cookieValue, params...)
	return token, err
}

// Parse JWT string from Authorization header.
func (a *jwtAuth) parseTokenFromHeader(req *http.Request) (string, error) {
	header := req.Header.Get("Authorization")

	if header == "" {
		return "", errors.New("no authorization header exists")
	}

	headerFields := strings.Fields(header)

	if len(headerFields) == 2 && headerFields[0] == "Bearer" {
		return headerFields[1], nil
	}

	return "", errors.New("invalid bearer token format")
}

func (a *jwtAuth) whitelist(req *http.Request) bool {
	path := req.URL.Path

	// If we set to 401 unauthorized, let the client handles the 401 itself
	if Config.JWTAuthNoTokenStatusCode == http.StatusUnauthorized {
		for _, p := range a.ExactWhitelistPaths {
			if p == path {
				return true
			}
		}
	}

	for _, p := range a.PrefixWhitelistPaths {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (a *jwtAuth) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	if a.whitelist(req) {
		next(w, req)
		return
	}

	var token jwt.Token

	// If key was unable to be parsed on auth init and not using JWKS, error out.
	if a.verificationKeyErr != nil && !Config.JWKSEnabled {
		jwtErrorHandler(w, req)
		return
	}

	// Look for JWT token in cookie.
	c, err := req.Cookie(Config.JWTAuthCookieTokenName)
	if err == nil {
		token, err = a.parseStringToToken(c.Value, a.parseOptions...)
		if err != nil {
			jwtErrorHandler(w, req)
			return
		}
	} else {
		// Look for JWT token in "Authorization" header.
		headerString, err := a.parseTokenFromHeader(req)
		if err != nil {
			jwtErrorHandler(w, req)
			return
		}

		token, err = a.parseStringToToken(headerString, a.parseOptions...)
		if err != nil {
			jwtErrorHandler(w, req)
			return
		}
	}

	// jwt.Validate() will validate the following fields if they exist on the JWT:
	// time-related components: "iat", "exp", and "nbf"
	if err := jwt.Validate(token); err != nil {
		jwtErrorHandler(w, req)
		return
	} else {
		// JWT is valid: add with context "Config.JWTAuthUserProperty" in order to access user claim in subject.go
		newRequest := req.WithContext(context.WithValue(req.Context(), a.userProperty, token))
		next(w, newRequest)
		return
	}
}

/**
setupBasicAuthMiddleware setup an BasicMiddleware from the ENV config
*/
func setupBasicAuthMiddleware() *basicAuth {
	return &basicAuth{
		Username:             []byte(Config.BasicAuthUsername),
		Password:             []byte(Config.BasicAuthPassword),
		PrefixWhitelistPaths: Config.BasicAuthPrefixWhitelistPaths,
		ExactWhitelistPaths:  Config.BasicAuthExactWhitelistPaths,
	}
}

type basicAuth struct {
	Username             []byte
	Password             []byte
	PrefixWhitelistPaths []string
	ExactWhitelistPaths  []string
}

func (a *basicAuth) whitelist(req *http.Request) bool {
	path := req.URL.Path

	for _, p := range a.ExactWhitelistPaths {
		if p == path {
			return true
		}
	}

	for _, p := range a.PrefixWhitelistPaths {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (a *basicAuth) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	if a.whitelist(req) {
		next(w, req)
		return
	}

	username, password, ok := req.BasicAuth()
	if !ok || subtle.ConstantTimeCompare(a.Username, []byte(username)) != 1 || subtle.ConstantTimeCompare(a.Password, []byte(password)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="you shall not pass"`)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	next(w, req)
}

type statsdMiddleware struct {
	StatsdClient *statsd.Client
}

func (s *statsdMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	defer func(start time.Time) {
		response := w.(negroni.ResponseWriter)
		status := strconv.Itoa(response.Status())
		duration := float64(time.Since(start)) / float64(time.Millisecond)
		tags := []string{
			"status:" + status,
			"path:" + r.RequestURI,
			"method:" + r.Method,
		}

		s.StatsdClient.Incr("http.requests.count", tags, 1)
		s.StatsdClient.TimeInMilliseconds("http.requests.duration", duration, tags, 1)
	}(time.Now())

	next(w, r)
}

type prometheusMiddleware struct {
	counter   *prometheus.CounterVec
	latencies *prometheus.HistogramVec
}

func (p *prometheusMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if r.URL.EscapedPath() == Global.Prometheus.ScrapePath {
		handler := promhttp.Handler()
		handler.ServeHTTP(w, r)
	} else {
		defer func(start time.Time) {
			response := w.(negroni.ResponseWriter)
			status := strconv.Itoa(response.Status())
			duration := float64(time.Since(start)) / float64(time.Second)

			p.counter.WithLabelValues(status, r.RequestURI, r.Method).Inc()
			if p.latencies != nil {
				p.latencies.WithLabelValues(status, r.RequestURI, r.Method).Observe(duration)
			}
		}(time.Now())
		next(w, r)
	}
}
