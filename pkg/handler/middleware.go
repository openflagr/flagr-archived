package handler

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/form3tech-oss/jwt-go"
	"github.com/gohttp/pprof"
	negronilogrus "github.com/meatballhat/negroni-logrus"
	"github.com/openflagr/flagr/pkg/config"
	"github.com/openflagr/flagr/pkg/entity"
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
	if config.Config.StatsdEnabled && config.Config.StatsdAPMEnabled {
		tracer.Stop()
	}
}

// Setupconfig.GlobalMiddleware setup the config.global middleware
func SetupGlobalMiddleware(handler http.Handler) http.Handler {
	n := negroni.New()

	if config.Config.MiddlewareGzipEnabled {
		n.Use(gzip.Gzip(gzip.DefaultCompression))
	}

	if config.Config.MiddlewareVerboseLoggerEnabled {
		middleware := negronilogrus.NewMiddlewareFromLogger(logrus.StandardLogger(), "flagr")

		for _, u := range config.Config.MiddlewareVerboseLoggerExcludeURLs {
			middleware.ExcludeURL(u)
		}

		n.Use(middleware)
	}

	if config.Config.StatsdEnabled {
		n.Use(&statsdMiddleware{StatsdClient: config.Global.StatsdClient})

		if config.Config.StatsdAPMEnabled {
			tracer.Start(
				tracer.WithAgentAddr(fmt.Sprintf("%s:%s", config.Config.StatsdHost, config.Config.StatsdAPMPort)),
				tracer.WithServiceName(config.Config.StatsdAPMServiceName),
			)
		}
	}

	if config.Config.PrometheusEnabled {
		n.Use(&prometheusMiddleware{
			counter:   config.Global.Prometheus.RequestCounter,
			latencies: config.Global.Prometheus.RequestHistogram,
		})
	}

	if config.Config.NewRelicEnabled {
		n.Use(&negroninewrelic.Newrelic{Application: &config.Global.NewrelicApp})
	}

	if config.Config.CORSEnabled {
		n.Use(cors.New(cors.Options{
			AllowedOrigins:   config.Config.CORSAllowedOrigins,
			AllowedHeaders:   config.Config.CORSAllowedHeaders,
			ExposedHeaders:   config.Config.CORSExposedHeaders,
			AllowedMethods:   config.Config.CORSAllowedMethods,
			AllowCredentials: config.Config.CORSAllowCredentials,
		}))
	}

	if config.Config.JWTAuthEnabled {
		n.Use(setupJWTAuthMiddleware())
	}

	if config.Config.BasicAuthEnabled {
		n.Use(setupBasicAuthMiddleware())
	}

	if config.Config.CasbinEnforcementEnabled {
		n.Use(setupCasbinMiddleware())
	}

	n.Use(&negroni.Static{
		Dir:       http.Dir("./browser/flagr-ui/dist/"),
		Prefix:    config.Config.WebPrefix,
		IndexFile: "index.html",
	})

	n.Use(setupRecoveryMiddleware())

	if config.Config.WebPrefix != "" {
		handler = http.StripPrefix(config.Config.WebPrefix, handler)
	}

	if config.Config.PProfEnabled {
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

/**
setupJWTAuthMiddleware setup an JWTMiddleware from the ENV config.config
*/
func setupJWTAuthMiddleware() *jwtAuth {
	var signingMethod jwt.SigningMethod
	var validationKey interface{}
	var errParsingKey error

	switch config.Config.JWTAuthSigningMethod {
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
		validationKey = []byte(config.Config.JWTAuthSecret)
	case "HS512":
		signingMethod = jwt.SigningMethodHS512
		validationKey = []byte(config.Config.JWTAuthSecret)
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
		validationKey, errParsingKey = jwt.ParseRSAPublicKeyFromPEM([]byte(config.Config.JWTAuthSecret))
	default:
		signingMethod = jwt.SigningMethodHS256
		validationKey = []byte("")
	}

	return &jwtAuth{
		PrefixWhitelistPaths: config.Config.JWTAuthPrefixWhitelistPaths,
		ExactWhitelistPaths:  config.Config.JWTAuthExactWhitelistPaths,
		JWTMiddleware: jwtmiddleware.New(jwtmiddleware.Options{
			ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
				return validationKey, errParsingKey
			},
			SigningMethod: signingMethod,
			Extractor: jwtmiddleware.FromFirst(
				func(r *http.Request) (string, error) {
					c, err := r.Cookie(config.Config.JWTAuthCookieTokenName)
					if err != nil {
						return "", nil
					}
					return c.Value, nil
				},
				jwtmiddleware.FromAuthHeader,
			),
			UserProperty: config.Config.JWTAuthUserProperty,
			Debug:        config.Config.JWTAuthDebug,
			ErrorHandler: jwtErrorHandler,
		}),
	}
}

func jwtErrorHandler(w http.ResponseWriter, r *http.Request, err string) {
	switch config.Config.JWTAuthNoTokenStatusCode {
	case http.StatusTemporaryRedirect:
		http.Redirect(w, r, config.Config.JWTAuthNoTokenRedirectURL, http.StatusTemporaryRedirect)
		return
	default:
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s"`, config.Config.JWTAuthNoTokenRedirectURL))
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
}

type jwtAuth struct {
	PrefixWhitelistPaths []string
	ExactWhitelistPaths  []string
	JWTMiddleware        *jwtmiddleware.JWTMiddleware
}

func (a *jwtAuth) whitelist(req *http.Request) bool {
	return checkJWTWhitelistPaths(req.URL.Path, a.ExactWhitelistPaths, a.PrefixWhitelistPaths)
}

func checkJWTWhitelistPaths(path string, exactPaths, prefixPaths []string) bool {
	// If we set to 401 unauthorized, let the client handles the 401 itself
	if config.Config.JWTAuthNoTokenStatusCode == http.StatusUnauthorized {
		for _, p := range exactPaths {
			if p == path {
				return true
			}
		}
	}

	for _, p := range prefixPaths {
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

	a.JWTMiddleware.HandlerWithNext(w, req, next)
}

/**
setupBasicAuthMiddleware setup an BasicMiddleware from the ENV config.config
*/
func setupBasicAuthMiddleware() *basicAuth {
	return &basicAuth{
		Username:             []byte(config.Config.BasicAuthUsername),
		Password:             []byte(config.Config.BasicAuthPassword),
		PrefixWhitelistPaths: config.Config.BasicAuthPrefixWhitelistPaths,
		ExactWhitelistPaths:  config.Config.BasicAuthExactWhitelistPaths,
	}
}

type basicAuth struct {
	Username             []byte
	Password             []byte
	PrefixWhitelistPaths []string
	ExactWhitelistPaths  []string
}

func (a *basicAuth) whitelist(req *http.Request) bool {
	return checkWhitelistPaths(req.URL.Path, a.ExactWhitelistPaths, a.PrefixWhitelistPaths)
}

func checkWhitelistPaths(path string, exactPaths, prefixPaths []string) bool {
	for _, p := range exactPaths {
		if p == path {
			return true
		}
	}

	for _, p := range prefixPaths {
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
	if r.URL.EscapedPath() == config.Global.Prometheus.ScrapePath {
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

func setupCasbinMiddleware() *casbinMiddleware {
	logrus.Debug("setting up Casbin middleware")

	return &casbinMiddleware{
		entity.GetRBACController(),
	}
}

type casbinMiddleware struct {
	rbac *entity.RBACController
}

func (rbacMiddleware *casbinMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !config.Config.JWTAuthEnabled {
		logrus.Error("JWT authorization is disabled, requests will be denied")

		http.Error(w, "Not authorized", http.StatusUnauthorized)

		return
	}

	// check the path against the JWT auth whitelist
	if checkJWTWhitelistPaths(r.URL.Path, config.Config.JWTAuthExactWhitelistPaths, config.Config.JWTAuthPrefixWhitelistPaths) {
		next(w, r)

		return
	}

	// get the claims from the JWT
	var user string
	var claim interface{}

	if token, ok := r.Context().Value(config.Config.JWTAuthUserProperty).(*jwt.Token); ok {
		claims := token.Claims.(jwt.MapClaims)
		user = claims[config.Config.JWTAuthUserClaim].(string)

		if claimField, ok := claims[config.Config.CasbinPassJWTClaimsField]; ok {
			claim = claimField
		}
	}

	// try to match the user with a policy
	var allow bool
	var err error

	if config.Config.CasbinPassJWTClaimsField != "" && claim != nil {
		allow, err = rbacMiddleware.rbac.Enforcer.Enforce(user, r.URL.Path, r.Method, claim)
	} else {
		allow, err = rbacMiddleware.rbac.Enforcer.Enforce(user, r.URL.Path, r.Method)
	}

	if err != nil {
		logrus.Errorf("Casbin enforcement error: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}

	if allow {
		next(w, r)
	} else {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}
