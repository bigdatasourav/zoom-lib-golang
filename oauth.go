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
)

var tokenCache = make(map[string]tokenInfo)

type tokenInfo struct {
	Token          string
	ExpirationTime time.Time
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func OAuthToken(accountID string, clientID string, clientSecret string) (string, error) {
	tokenData, exists := tokenCache[accountID+clientID]

	if exists && !tokenData.ExpirationTime.Before(time.Now()) {
		return tokenData.Token, nil
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

	// set the expiration time for the token to be 5 minutes less than the actual expiry time
	expirationTime := time.Now().Add(time.Second * time.Duration(accessTokenResp.ExpiresIn-300))
	tokenData = tokenInfo{
		Token:          accessTokenResp.AccessToken,
		ExpirationTime: expirationTime,
	}

	tokenCache[accountID+clientID] = tokenData

	return accessTokenResp.AccessToken, nil
}
