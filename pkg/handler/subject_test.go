package handler

import (
	"context"
	"net/http"
	"testing"

	jwt "github.com/lestrrat-go/jwx/jwt"
	"github.com/openflagr/flagr/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestGetSubjectFromJWT(t *testing.T) {
	var ctx context.Context

	defer func() { config.Config.JWTAuthEnabled = false }()
	config.Config.JWTAuthEnabled = true

	r, _ := http.NewRequest("GET", "", nil)
	assert.Equal(t, getSubjectFromRequest(r), "")

	ctx = context.TODO()
	assert.Equal(t, getSubjectFromRequest(r.WithContext(ctx)), "")

	userProperty := config.UserPropertyType(config.Config.JWTAuthUserProperty)
	token, _ := jwt.Parse([]byte{})

	//nolint:staticcheck // jwt-middleware is using the string type of context key
	ctx = context.WithValue(ctx, userProperty, token)
	assert.Equal(t, getSubjectFromRequest(r.WithContext(ctx)), "")

	token, _ = jwt.Parse([]byte(`{"sub": "foo@example.com"}`))
	//nolint:staticcheck // jwt-middleware is using the string type of context key
	ctx = context.WithValue(ctx, userProperty, token)
	assert.Equal(t, getSubjectFromRequest(r.WithContext(ctx)), "foo@example.com")
}

func TestGetSubjectFromOauthProxy(t *testing.T) {
	var ctx = context.Background()

	defer func() { config.Config.HeaderAuthEnabled = false }()
	config.Config.HeaderAuthEnabled = true

	r, _ := http.NewRequest("GET", "", nil)
	assert.Equal(t, getSubjectFromRequest(r), "")

	r.Header.Set(config.Config.HeaderAuthUserField, "foo@example.com")
	assert.Equal(t, getSubjectFromRequest(r.WithContext(ctx)), "foo@example.com")
}
