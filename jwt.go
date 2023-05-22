package zoom

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func jwtToken(key string, secret string) (string, error) {
	claims := &jwt.StandardClaims{
		Issuer:    key,
		ExpiresAt: jwt.TimeFunc().Local().Add(time.Second * time.Duration(5000)).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["alg"] = "HS256"
	token.Header["typ"] = "JWT"

	return token.SignedString([]byte(secret))
}

func (c *Client) addRequestAuth(req *http.Request, err error) (*http.Request, error) {
	if err != nil {
		return nil, err
	}

	var token string
	if c.AccountID != "" {
		// establish Server-to-Server OAuth token
		oAuthToken, oauthErr := OAuthToken(c.AccountID, c.ClientID, c.ClientSecret)
		if oauthErr != nil {
			return nil, oauthErr
		}
		token = oAuthToken
	} else {
		// establish JWT token
		jwtToken, jwtErr := jwtToken(c.Key, c.Secret)
		if jwtErr != nil {
			return nil, jwtErr
		}
		token = jwtToken
	}

	// set token in authorization header
	req.Header.Add("Authorization", "Bearer "+token)

	return req, nil
}
