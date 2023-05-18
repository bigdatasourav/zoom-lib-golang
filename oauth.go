package zoom

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

const (
	SessionName        = "zoom_oauth_session"
	SessionAccessToken = "access_token"
	SessionExpiry      = "expiry"
)

var store = sessions.NewCookieStore([]byte("zoom_oauth_store"))

func OAuthToken(r *http.Request, accountID string, clientID string, clientSecret string) (string, error) {
	session, err := store.Get(r, SessionName)
	if err != nil {
		return "", err
	}

	// Check if a cached access token exists and is still valid
	if accessToken, ok := session.Values[SessionAccessToken]; ok {
		expiry, ok := session.Values[SessionExpiry].(time.Time)
		if ok && time.Now().Before(expiry) {
			return accessToken.(string), nil
		}
	}

	data := url.Values{}
	data.Set("grant_type", "account_credentials")
	data.Set("account_id", accountID)

	req, err := http.NewRequest("POST", "https://zoom.us/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	credentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credentials))
	req.Header.Set("Host", "zoom.us")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	var accessTokenResp AccessTokenResponse
	err = json.Unmarshal(body, &accessTokenResp)
	if err != nil {
		return "", err
	}

	// Cache the new access token and expiry time in the session
	session.Values[SessionAccessToken] = accessTokenResp.AccessToken
	session.Values[SessionExpiry] = time.Now().Add(time.Duration(accessTokenResp.ExpiresIn) * time.Second)
	if err := store.Save(r, nil, session); err != nil {
		return "", err
	}

	panic(accessTokenResp.AccessToken)
	return accessTokenResp.AccessToken, nil
}

func (c *Client) addRequestAuth(req *http.Request, err error) (*http.Request, error) {
	if err != nil {
		return nil, err
	}

	// establish Server-to-Server OAuth token
	ss, err := OAuthToken(req, c.AccountID, c.ClientID, c.ClientSecret)
	if err != nil {
		return nil, err
	}

	// set Server-to-Server OAuth Authorization header
	req.Header.Add("Authorization", "Bearer "+ss)

	return req, nil
}
