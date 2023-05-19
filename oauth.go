package zoom

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func OAuthToken(accountID string, clientID string, clientSecret string) (string, error) {
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

	return accessTokenResp.AccessToken, nil
}

func (c *OAuthClient) addRequestAuth(req *http.Request, err error) (*http.Request, error) {
	if err != nil {
		return nil, err
	}

	// establish Server-to-Server OAuth token
	ss, err := OAuthToken(c.AccountID, c.ClientID, c.ClientSecret)
	if err != nil {
		return nil, err
	}

	// set Server-to-Server OAuth Authorization header
	req.Header.Add("Authorization", "Bearer "+ss)

	return req, nil
}
