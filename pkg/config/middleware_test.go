package config

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

type okHandler struct{}

const (
	// Signed with secret: ""
	validHS256JWTToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmbGFncl91c2VyIjoiMTIzNDU2Nzg5MCJ9.CLXgNEtwPCqCOtUU-KmqDyO8S2wC_G6PZ0tml8DCuNw"

	validRS256JWTToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"

	validRS256PublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`

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

	Config.NewRelicEnabled = true
	hh = SetupGlobalMiddleware(h)
	assert.NotNil(t, hh)
	Config.NewRelicEnabled = false

	Config.JWTAuthEnabled = true
	hh = SetupGlobalMiddleware(h)
	assert.NotNil(t, hh)
	Config.JWTAuthEnabled = false

	Config.PProfEnabled = false
	hh = SetupGlobalMiddleware(h)
	assert.NotNil(t, hh)
	Config.PProfEnabled = true
}

func resetJWTConfig() {
	Config.JWTAuthEnabled = false
	Config.JWTAuthSigningMethod = "HS256"
	Config.JWTAuthSecret = ""
}

func TestJWTAuthMiddleware(t *testing.T) {
	h := &okHandler{}

	t.Run("it will redirect if jwt enabled but no cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)

		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if jwt enabled with wrong cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		defer resetJWTConfig()
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
		Config.JWTAuthEnabled = true
		defer resetJWTConfig()
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
		Config.JWTAuthEnabled = true
		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:18000%s", Config.JWTAuthPrefixWhitelistPaths[0]), nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if jwt enabled with correct header token", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+validHS256JWTToken)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will redirect if jwt enabled with malformed header token", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer ")
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if jwt enabled with invalid cookie token and valid header token", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		defer resetJWTConfig()
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
		Config.JWTAuthEnabled = true
		Config.JWTAuthSigningMethod = "RS256"
		defer resetJWTConfig()
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

	t.Run("it will pass if jwt enabled with correct header token encrypted using RS256 (with PKIX secret)", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthSigningMethod = "RS256"
		Config.JWTAuthSecret = validRS256PublicKey
		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+validRS256JWTToken)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if jwt enabled with correct header token encrypted using RS256 (with certificate secret)", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthSigningMethod = "RS256"
		Config.JWTAuthSecret = `-----BEGIN CERTIFICATE-----
MIICfzCCAWegAwIBAgIBATANBgkqhkiG9w0BAQsFADAAMCAXDTIyMDIwOTE0NDM1
NloYDzAwMDEwMTAxMDAwMDAwWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAmwyWBtLKc3JRHYUBeaX0VdE9emdfOsp3uSn9ecSXrD/5qLr84gYR+nm4
Z1pi+GUnH/5ePDAlzOqomnXdKlGUfFKOKrBPCtT3ZwZTD/IuMF3g50T0Ku/is8lY
ol5W5G6pEdkgjxMIpuK9Psq/jsPZMrafjYJ0LtaJpJbGURUr0MaIaIJHXV3+RHYI
pOXMbXGtW5QfopKSOnBsEuGMyPTXxshXxh8nYQoFvva9wyZaqh4UjkBI66E1XPqo
Qgyjr4Fq6KqP0foK1ZBGZfNuyxAXvKDQBqqSV+rXth2H/Be8+Umdb88TFkTJ7+yy
UG+LQgkVpVXcpH9B16Ufbi/m51iHrwIDAQABowIwADANBgkqhkiG9w0BAQsFAAOC
AQEAgYSMw8XzTTCG0ejEoDub02pnw6tOJRgAvUV3vgzh7aubQoL7d57LNdJF31/Z
5AP6Bf8cdU7w5/lqIyomB/km0Attus9YACw+D7evHOIGaqaDcYzuZjF4wv9Zw0qb
TusyO1eacw+ZfZmAgOO5BW14GtaoOcvmVqt5cavg3741Z4GVm4k2H69tJRXPOY0f
WjtaeR5YNC7yw+al50Vqp4f3iI34JpXifxBmq2oivYUzWvCt50kXpmxb/TpeGPh2
hXvoCLn8YyaN6Wyjy7VeFBY7Zh1bAmgBsFw7+fpiTZXekzm3uQw/jD9bTV+XqTXI
PJ+pcTxHhl4wwWtxAvMFwMtzIA==
-----END CERTIFICATE-----`

		validRS256TokenFromCert := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.K-VJXo6VluUur_dTXaTX1zBhZnkKDUzF_pOZis2TliaIJgRdt-8dNPGCf9MVdlnREKY3I3jEV_mFfzkreB2Q40MAkssKWwnJN586a1SHx0KUTvIOp5cyz0wCnUo7vd7vye_8pSTh_uZp1kS3afukUwYpyzimv51nVr4dWWV7uA5TvJtpowQ5A1L8A2yzI3rHgFfxnByQ6RQewfd_iGgP8n-A_W25LBXjLjr0yXCMfvnXn2mD5IevVBnWmywAbjagELmGRdWqeV3rHK-fFbCsYwje_5u1fFiw0lehQ6sTd973-YiqPODLZJd0kdFEfo6_FZ0WhYnpF-C7gtReUPzoAQ"

		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+validRS256TokenFromCert)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will redirect if given invalid secret", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthSigningMethod = "RS256"
		Config.JWTAuthSecret = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDhM3uNuWlv0fxS
hQ7AGcIpVU8ICu26C7iNnqMOlrdYszN7pTU39JhMgOPOFpi+5f1S27GsyZP2ecQK
HonTc+XWgRye0nt9QEuRCvnyttUlrVjzii4uXNZdICalt+fdCtisJrEKZXTjaMDK
M9FnsAy0sns3uvMgXVM4NOmqFA==
-----END PRIVATE KEY-----`

		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+validRS256JWTToken)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will pass if jwt enabled with valid cookie token with passphrase", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthSecret = "mysecret"
		defer resetJWTConfig()
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
		Config.JWTAuthEnabled = true
		Config.JWTAuthSigningMethod = "invalid"
		defer resetJWTConfig()
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
		Config.JWTAuthEnabled = true
		Config.JWTAuthSecret = "mysecret"
		Config.JWTAuthSigningMethod = "HS512"
		defer resetJWTConfig()
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

	t.Run("it will redirect if jwt enabled with invalid RS256 header token", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthSigningMethod = "RS256"
		Config.JWTAuthSecret = validRS256PublicKey
		defer resetJWTConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer invalid_token")
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if jwt enabled with invalid RS256 cookie", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthSigningMethod = "RS256"
		Config.JWTAuthSecret = validRS256PublicKey
		defer resetJWTConfig()
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
}

func createJWKSandKey(t *testing.T, alg jwa.SignatureAlgorithm, kid string, includeKid bool, includeAlg bool) (jwk.Key, jwk.Key) {
	// Create private key
	var rawPrivKeyInterface interface{}
	var pubKey jwk.Key
	var err error
	var jwkKID string

	switch alg {
	case jwa.RS256:
		rawPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate private key: %s\n", err)
			return nil, nil
		}

		// Create public key for JWKS (JWT verification).
		pubKey, err = jwk.New(rawPrivKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create public key: %s\n", err)
			return nil, nil
		}

		rawPrivKeyInterface = interface{}(rawPrivKey)

	default:
		rawPrivKey := make([]byte, 64)
		rand.Read(rawPrivKey)

		pubKey, err = jwk.New(rawPrivKey)
		if err != nil {
			t.Fatalf("Failed to create public key: %s\n", err)
			return nil, nil
		}

		rawPrivKeyInterface = interface{}(rawPrivKey)
	}

	jwkKID = "key-" + kid

	// Create JWK to sign the token.
	privKey, err := jwk.New(rawPrivKeyInterface)
	if err != nil {
		t.Fatalf("Failed to create JWK: %s\n", err)
		return nil, nil
	}

	// Set kID on private key.
	if includeKid {
		privKey.Set(jwk.KeyIDKey, jwkKID)
		pubKey.Set(jwk.KeyIDKey, jwkKID)
	}

	// Set kID and alg on public key.
	if includeAlg {
		pubKey.Set(jwk.AlgorithmKey, alg)
	}

	return pubKey, privKey
}

func createJWT(t *testing.T, key jwk.Key, alg jwa.SignatureAlgorithm, exp int64) string {
	// Create the token.
	token := jwt.New()
	token.Set("user", "test_user")
	token.Set("exp", exp)

	// Sign the token with the JWK and generate a payload.
	signed, err := jwt.Sign(token, alg, key)
	if err != nil {
		t.Fatalf("Failed to sign the JWT: %s\n", err)
		return ""
	}

	// Convert []byte to string.
	tokenString := string(signed)

	return tokenString
}

func resetJWKSConfig() {
	Config.JWTAuthEnabled = false
	Config.JWKSEnabled = false
	Config.JWKSURL = ""
	Config.JWKSUseDefaultKey = false
	Config.JWKSInferAlgorithmFromKey = false
}

func TestJWKS(t *testing.T) {
	h := &okHandler{}

	invalidEXP := time.Now().Add(-10 * time.Hour).Unix()
	validEXP := time.Now().Add(10 * time.Hour).Unix()

	mockRS256PublicKey, mockRS256PrivateKey := createJWKSandKey(t, jwa.RS256, jwa.RS256.String(), true, true)
	mockHS256PublicKey, mockHS256PrivateKey := createJWKSandKey(t, jwa.HS256, jwa.HS256.String(), true, true)
	mockHS512PublicKey, mockHS512PrivateKey := createJWKSandKey(t, jwa.HS512, jwa.HS512.String(), true, true)

	vaildRS256JWT := createJWT(t, mockRS256PrivateKey, jwa.RS256, validEXP)
	vaildHS256JWT := createJWT(t, mockHS256PrivateKey, jwa.HS256, validEXP)
	vaildHS512JWT := createJWT(t, mockHS512PrivateKey, jwa.HS512, validEXP)
	invalidRS256JWT := createJWT(t, mockRS256PrivateKey, jwa.RS256, invalidEXP)

	// Create new JWKS with public key.
	validJWKS := jwk.NewSet()
	validJWKS.Add(mockRS256PublicKey)
	validJWKS.Add(mockHS256PublicKey)
	validJWKS.Add(mockHS512PublicKey)

	// Format JWKS for server.
	mockJWKS, err := json.MarshalIndent(validJWKS, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JWKS: %s\n", err)
	}

	// JWKS server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mockJWKS)
	}))
	defer srv.Close()

	// ENV cases
	t.Run("it will fail if JWT and JWKS are enabled with no JWKSURL", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true

		defer resetJWKSConfig()

		hh := SetupGlobalMiddleware(h)
		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will fail if JWT and JWKS are enabled with JWKSInferAlgorithmFromKey", func(t *testing.T) {
		// Create public and private key without an "alg" field.
		missingAlgRS256PublicKey, missingAlgRS256PrivateKey := createJWKSandKey(t, jwa.RS256, "missing-alg", true, false)

		missingAlgRS256JWT := createJWT(t, missingAlgRS256PrivateKey, jwa.RS256, validEXP)
		missingAlgJWKS := jwk.NewSet()
		missingAlgJWKS.Add(missingAlgRS256PublicKey)

		mockMissingAlgJWKS, err := json.MarshalIndent(missingAlgJWKS, "", "  ")
		if err != nil {
			t.Fatalf("Failed to marshal JWKS: %s\n", err)
		}

		missingAlgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(mockMissingAlgJWKS)
		}))

		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = missingAlgSrv.URL
		Config.JWKSInferAlgorithmFromKey = true

		defer func() {
			Config.JWTAuthEnabled = false
			Config.JWKSEnabled = false
			Config.JWKSURL = ""
			Config.JWKSInferAlgorithmFromKey = false
			missingAlgSrv.Close()
		}()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+missingAlgRS256JWT)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will fail if JWT and JWKS are enabled with JWKSUseDefaultKey", func(t *testing.T) {
		// Create public and private key without a "kid" field.
		missingKidRS256PublicKey, missingKidRS256PrivateKey := createJWKSandKey(t, jwa.RS256, "missing-kid", false, true)

		// Create JWT without a "kid" field.
		missingKidRS256JWT := createJWT(t, missingKidRS256PrivateKey, jwa.RS256, validEXP)
		missingKidJWKS := jwk.NewSet()
		missingKidJWKS.Add(missingKidRS256PublicKey)

		// Format JWKS for server.
		mockMissingKidJWKS, err := json.MarshalIndent(missingKidJWKS, "", "  ")
		if err != nil {
			t.Fatalf("Failed to marshal JWKS: %s\n", err)
		}

		missingKidSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(mockMissingKidJWKS)
		}))

		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = missingKidSrv.URL
		Config.JWKSUseDefaultKey = true

		defer func() {
			Config.JWTAuthEnabled = false
			Config.JWKSEnabled = false
			Config.JWKSURL = ""
			Config.JWKSUseDefaultKey = false
			missingKidSrv.Close()
		}()

		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+missingKidRS256JWT)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will fail if JWKS is unable to be fetched", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = "www.test.com/jwks"

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+vaildRS256JWT)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	// HEADER cases
	t.Run("it will redirect if JWT and JWKS are enabled with no header on request", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if JWT and JWKS are enabled with no valid JWT in header", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer invalid_token")
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if JWT and JWKS are enabled with expired JWT in header", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+invalidRS256JWT)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will pass if JWT and JWKS enabled with correct RS256 JWT in header", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+vaildRS256JWT)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if JWT and JWKS enabled with correct HS256 JWT in header", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+vaildHS256JWT)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if JWT and JWKS are enabled with correct HS512 JWT in header", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.Header.Add("Authorization", "Bearer "+vaildHS512JWT)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	// COOKIE cases
	t.Run("it will redirect if JWT and JWKS are enabled but no cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)

		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusTemporaryRedirect, res.Code)
	})

	t.Run("it will redirect if JWT and JWKS are enabled with invalid cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
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

	t.Run("it will pass if JWT and JWKS enabled with correct RS256 cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: vaildRS256JWT,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if JWT and JWKS enabled with correct HS256 cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: vaildHS256JWT,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will pass if JWT and JWKS enabled with correct HS512 cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWKSEnabled = true
		Config.JWKSURL = srv.URL

		defer resetJWKSConfig()
		hh := SetupGlobalMiddleware(h)

		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: vaildHS512JWT,
		})
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})
}

func TestJWTAuthMiddlewareWithUnauthorized(t *testing.T) {
	h := &okHandler{}

	t.Run("it will return 401 if no cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer func() {
			Config.JWTAuthEnabled = false
			Config.JWTAuthNoTokenStatusCode = http.StatusTemporaryRedirect
		}()

		hh := SetupGlobalMiddleware(h)
		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusUnauthorized, res.Code)
	})

	t.Run("it will return 200 if cookie passed", func(t *testing.T) {
		Config.JWTAuthEnabled = true
		Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer func() {
			Config.JWTAuthEnabled = false
			Config.JWTAuthNoTokenStatusCode = http.StatusTemporaryRedirect
		}()

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
		Config.JWTAuthEnabled = true
		Config.JWTAuthNoTokenStatusCode = http.StatusUnauthorized
		defer func() {
			Config.JWTAuthEnabled = false
			Config.JWTAuthNoTokenStatusCode = http.StatusTemporaryRedirect
		}()

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
		Config.BasicAuthEnabled = true
		Config.BasicAuthUsername = "admin"
		Config.BasicAuthPassword = "password"
		defer func() {
			Config.BasicAuthEnabled = false
			Config.BasicAuthUsername = ""
			Config.BasicAuthPassword = ""
		}()

		hh := SetupGlobalMiddleware(h)
		res := httptest.NewRecorder()
		res.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", "http://localhost:18000/api/v1/flags", nil)
		hh.ServeHTTP(res, req)
		assert.Equal(t, http.StatusOK, res.Code)
	})

	t.Run("it will return 401 for web paths when enabled and no basic auth passed", func(t *testing.T) {
		Config.BasicAuthEnabled = true
		Config.BasicAuthUsername = "admin"
		Config.BasicAuthPassword = "password"
		defer func() {
			Config.BasicAuthEnabled = false
			Config.BasicAuthUsername = ""
			Config.BasicAuthPassword = ""
		}()

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
		Config.BasicAuthEnabled = true
		Config.BasicAuthUsername = "admin"
		Config.BasicAuthPassword = "password"
		defer func() {
			Config.BasicAuthEnabled = false
			Config.BasicAuthUsername = ""
			Config.BasicAuthPassword = ""
		}()

		testPaths := []string{"/", "", "/#", "/#/", "/static", "/static/"}
		for _, path := range testPaths {
			t.Run(fmt.Sprintf("path: %s", path), func(t *testing.T) {
				hh := SetupGlobalMiddleware(h)
				res := httptest.NewRecorder()
				res.Body = new(bytes.Buffer)
				req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:18000%s", path), nil)
				req.SetBasicAuth(Config.BasicAuthUsername, Config.BasicAuthPassword)
				hh.ServeHTTP(res, req)
				assert.Equal(t, http.StatusOK, res.Code)
			})
		}
	})

}
