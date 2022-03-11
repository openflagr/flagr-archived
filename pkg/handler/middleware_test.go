package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openflagr/flagr/pkg/config"
	"github.com/openflagr/flagr/pkg/entity"
	"github.com/stretchr/testify/assert"
)

type okHandler struct{}

const (
	// Signed with secret: ""
	validHS256JWTToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmbGFncl91c2VyIjoiMTIzNDU2Nzg5MCJ9.CLXgNEtwPCqCOtUU-KmqDyO8S2wC_G6PZ0tml8DCuNw"

	// Public Key:
	//-----BEGIN PUBLIC KEY-----
	//MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
	//UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
	//HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
	//o2kQ+X5xK9cipRgEKwIDAQAB
	//-----END PUBLIC KEY-----
	validRS256JWTToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"

	// Signed with secret: "mysecret"
	validHS256JWTTokenWithSecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.drt_po6bHhDOF_FJEHTrK-KD8OGjseJZpHwHIgsnoTM"

	// Signed with secret: "mysecret"
	validHS512JWTTokenWithSecret = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.G4VTPaWRHtByF6SaHSQFTeu-896jFb2dF2KnYjJTa9MY_a6Tbb9BsO7Uu0Ju_QOGGDI_b-k6U0T6qwj9lA5_Aw"
)

func (o *okHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("OK"))
}

func TestSetupGlobalMiddleware(t *testing.T) {
	var h, hh http.Handler

	hh = SetupGlobalMiddleware(h)
	assert.NotNil(t, hh)

	config.Config.NewRelicEnabled = true
	hh = SetupGlobalMiddleware(h)
	assert.NotNil(t, hh)
	config.Config.NewRelicEnabled = false

	config.Config.JWTAuthEnabled = true
	hh = SetupGlobalMiddleware(h)
	assert.NotNil(t, hh)
	config.Config.JWTAuthEnabled = false

	config.Config.PProfEnabled = false
	hh = SetupGlobalMiddleware(h)
	assert.NotNil(t, hh)
	config.Config.PProfEnabled = true
}

func TestJWTAuthMiddleware(t *testing.T) {
	h := &okHandler{}

	t.Run("it will redirect if jwt enabled but no cookie passed", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)

		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if jwt enabled with wrong cookie passed", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: "invalid_jwt",
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will pass if jwt enabled with correct cookie passed", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS256JWTToken,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if jwt enabled but with whitelisted path", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:18000%s", config.Config.JWTAuthPrefixWhitelistPaths[0]), nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if jwt enabled with correct header token", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+validHS256JWTToken)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will redirect if jwt enabled with invalid cookie token and valid header token", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: "invalid_jwt",
		})
		req.Header.Add("Authorization", "Bearer "+validHS256JWTToken)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if jwt enabled and a cookie token encrypted with the wrong method", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSigningMethod = "RS256"
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: "invalid_jwt",
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will pass if jwt enabled with correct header token encrypted using RS256", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSigningMethod = "RS256"
		config.Config.JWTAuthSecret = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+validRS256JWTToken)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if jwt enabled with valid cookie token with passphrase", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSecret = "mysecret"
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS256JWTTokenWithSecret,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass with a correct HS256 token cookie when signing method is wrong and it defaults to empty string secret", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSigningMethod = "invalid"
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS256JWTToken,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if jwt enabled with correct header token encrypted using HS512", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSecret = "mysecret"
		config.Config.JWTAuthSigningMethod = "HS512"
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS512JWTTokenWithSecret,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})
}

func TestJWTAuthMiddlewareWithUnauthorized(t *testing.T) {
	h := &okHandler{}

	t.Run("it will return 401 if no cookie passed", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)
		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusUnauthorized, res.Code)
	})

	t.Run("it will return 200 if cookie passed", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)
		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS256JWTToken,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will return 200 for some paths", func(t *testing.T) {
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer config.ResetConfig()

		testPaths := []string{"/", "", "/#", "/#/", "/static", "/static/"}
		for _, path := range testPaths {
			t.Run(fmt.Sprintf("path: %s", path), func(t *testing.T) {
				hh := SetupGlobalMiddleware(h)
				res := httptest.NewRecorder()
				res.Body = new(bytes.Buffer)
				req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:18000%s", path), nil)
				hh.ServeHTTP(res, req)
				assert.Equal(t, http.StatusOK, res.Code)
			})
		}
	})
}

func TestBasicAuthMiddleware(t *testing.T) {
	h := &okHandler{}

	t.Run("it will return 200 for web paths when disabled", func(t *testing.T) {
		testPaths := []string{"/", "", "/#", "/#/", "/static", "/static/"}
		for _, path := range testPaths {
			t.Run(fmt.Sprintf("path: %s", path), func(t *testing.T) {
				hh := SetupGlobalMiddleware(h)
				res := httptest.NewRecorder()
				res.Body = new(bytes.Buffer)
				req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:18000%s", path), nil)
				hh.ServeHTTP(res, req)
				assert.Equal(t, http.StatusOK, res.Code)
			})
		}
	})

	t.Run("it will return 200 for whitelist path if basic auth is enabled", func(t *testing.T) {
		config.Config.BasicAuthEnabled = true
		config.Config.BasicAuthUsername = "admin"
		config.Config.BasicAuthPassword = "password"
		defer config.ResetConfig()

		hh := SetupGlobalMiddleware(h)
		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will return 401 for web paths when enabled and no basic auth passed", func(t *testing.T) {
		config.Config.BasicAuthEnabled = true
		config.Config.BasicAuthUsername = "admin"
		config.Config.BasicAuthPassword = "password"
		defer config.ResetConfig()

		testPaths := []string{"/", "", "/#", "/#/", "/static", "/static/"}
		for _, path := range testPaths {
			t.Run(fmt.Sprintf("path: %s", path), func(t *testing.T) {
				hh := SetupGlobalMiddleware(h)
				res := httptest.NewRecorder()
				res.Body = new(bytes.Buffer)
				req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:18000%s", path), nil)
				hh.ServeHTTP(res, req)
				assert.Equal(t, http.StatusUnauthorized, res.Code)
			})
		}
	})

	t.Run("it will return 200 for web paths when enabled and basic auth passed", func(t *testing.T) {
		config.Config.BasicAuthEnabled = true
		config.Config.BasicAuthUsername = "admin"
		config.Config.BasicAuthPassword = "password"
		defer config.ResetConfig()

		testPaths := []string{"/", "", "/#", "/#/", "/static", "/static/"}
		for _, path := range testPaths {
			t.Run(fmt.Sprintf("path: %s", path), func(t *testing.T) {
				hh := SetupGlobalMiddleware(h)
				res := httptest.NewRecorder()
				res.Body = new(bytes.Buffer)
				req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:18000%s", path), nil)
				req.SetBasicAuth(config.Config.BasicAuthUsername, config.Config.BasicAuthPassword)
				hh.ServeHTTP(res, req)
				assert.Equal(t, http.StatusOK, res.Code)
			})
		}
	})
}

func TestCasbinMiddleware(t *testing.T) {
	t.Run("allow a request with JWT auth that matches a policy", func(t *testing.T) {
		config.Config.CasbinEnforcementEnabled = true
		config.Config.CasbinModelPath = "testdata/rbac_model.conf"
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSecret = "mysecret"
		config.Config.JWTAuthSigningMethod = "HS512"
		defer config.ResetConfig()

		entity.SetupTestingRBACController()

		handler := SetupGlobalMiddleware(&okHandler{})

		entity.GetRBACController().Enforcer.AddPolicy("1234567890", "/api/v1/policy", "GET")

		res := httptest.NewRecorder()
		res.Body = bytes.NewBuffer([]byte{})
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/policy", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS512JWTTokenWithSecret,
		})

		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("deny a request with JWT auth that does not match a policy", func(t *testing.T) {
		config.Config.CasbinEnforcementEnabled = true
		config.Config.CasbinModelPath = "testdata/rbac_model.conf"
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSecret = "mysecret"
		config.Config.JWTAuthSigningMethod = "HS512"
		defer config.ResetConfig()

		entity.SetupTestingRBACController()

		handler := SetupGlobalMiddleware(&okHandler{})

		res := httptest.NewRecorder()
		res.Body = bytes.NewBuffer([]byte{})
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/policy", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS512JWTTokenWithSecret,
		})

		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusForbidden, res.Code)
	})

	t.Run("allow a request with whitelisted path that matches a policy", func(t *testing.T) {
		config.Config.CasbinEnforcementEnabled = true
		config.Config.CasbinModelPath = "testdata/rbac_model.conf"
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSecret = "mysecret"
		config.Config.JWTAuthSigningMethod = "HS512"
		config.Config.JWTAuthExactWhitelistPaths = []string{"/api/v1/policy"}
		config.Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer config.ResetConfig()

		entity.SetupTestingRBACController()

		handler := SetupGlobalMiddleware(&okHandler{})

		entity.GetRBACController().Enforcer.AddPolicy("1234567890", "/api/v1/policy", "GET")

		res := httptest.NewRecorder()
		res.Body = bytes.NewBuffer([]byte{})
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/policy", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS512JWTTokenWithSecret,
		})

		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("allow a request with whitelisted path that does not match a policy", func(t *testing.T) {
		config.Config.CasbinEnforcementEnabled = true
		config.Config.CasbinModelPath = "testdata/rbac_model.conf"
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSecret = "mysecret"
		config.Config.JWTAuthSigningMethod = "HS512"
		config.Config.JWTAuthExactWhitelistPaths = []string{"/api/v1/policy"}
		config.Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer config.ResetConfig()

		entity.SetupTestingRBACController()

		handler := SetupGlobalMiddleware(&okHandler{})

		res := httptest.NewRecorder()
		res.Body = bytes.NewBuffer([]byte{})
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/policy", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: validHS512JWTTokenWithSecret,
		})

		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("deny a request with no auth method enabled", func(t *testing.T) {
		config.Config.CasbinEnforcementEnabled = true
		config.Config.CasbinModelPath = "testdata/rbac_model.conf"
		defer config.ResetConfig()

		entity.SetupTestingRBACController()

		handler := SetupGlobalMiddleware(&okHandler{})

		res := httptest.NewRecorder()
		res.Body = bytes.NewBuffer([]byte{})
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/policy", strings.NewReader(`{}`))

		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusUnauthorized, res.Code)
	})

	t.Run("allow a request with JWT auth role claim that matches a policy", func(t *testing.T) {
		// role: "AdminRole"
		jwtToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlcyI6WyJBZG1pblJvbGUiXX0.W9ziE3Q6iYBlwMQHU9qOz1o7LmglFa5npvJVG8xO0iSC8uLuhchXNnPJrNUFXaYtYUwk4OpKhjny7AbLyfGqwQ"

		config.Config.CasbinEnforcementEnabled = true
		config.Config.CasbinModelPath = "testdata/rbac_with_jwt_role_model.conf"
		config.Config.CasbinPassJWTClaimsField = "roles"
		config.Config.JWTAuthEnabled = true
		config.Config.JWTAuthSecret = "mysecret"
		config.Config.JWTAuthSigningMethod = "HS512"
		defer config.ResetConfig()

		entity.SetupTestingRBACController()

		handler := SetupGlobalMiddleware(&okHandler{})

		entity.GetRBACController().Enforcer.AddPolicy("AdminRole", "/api/v1/policy", "GET")

		res := httptest.NewRecorder()
		res.Body = bytes.NewBuffer([]byte{})
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/policy", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: jwtToken,
		})

		handler.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})
}
