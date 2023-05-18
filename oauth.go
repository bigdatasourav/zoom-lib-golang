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
	TokenType   string `json:"token_type"`
}

func OAuth2Token(clientID string, clientSecret string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "account_credentials")
	data.Set("account_id", "Xt1aUD4WQ56w7hDhVbtDpg")

	req, err := http.NewRequest("POST", "https://zoom.us/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		panic("http" + err.Error())
	}

	credentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credentials))
	req.Header.Set("Host", "zoom.us")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic("do" + err.Error())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic("ioutil" + err.Error())
	}

	var accessTokenResp AccessTokenResponse
	err = json.Unmarshal(body, &accessTokenResp)
	if err != nil {
		panic("Unmarshal" + err.Error())
	}

	return accessTokenResp.AccessToken, nil
}

func (c *Client) addRequestAuth(req *http.Request, err error) (*http.Request, error) {
	if err != nil {
		return nil, err
	}

	// establish OAuth2Token token
	ss, err := OAuth2Token(c.Key, c.Secret)
	if err != nil {
		return nil, err
	}

	// set OAuth2Token Authorization header
	req.Header.Add("Authorization", "Bearer "+ss)

	return req, nil
}
