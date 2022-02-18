package handler

import (
	"net/http"

	"github.com/openflagr/flagr/pkg/config"
	"github.com/openflagr/flagr/pkg/util"

	"github.com/lestrrat-go/jwx/jwt"
)

func getSubjectFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}

	userProperty := config.UserPropertyType(config.Config.JWTAuthUserProperty)

	if config.Config.JWTAuthEnabled {
		token, ok := r.Context().Value(userProperty).(jwt.Token)
		if !ok {
			return ""
		}

		if v, ok := token.Get(config.Config.JWTAuthUserClaim); ok {
			return util.SafeString(v)
		}

	} else if config.Config.HeaderAuthEnabled {
		return r.Header.Get(config.Config.HeaderAuthUserField)
	}

	return ""
}
