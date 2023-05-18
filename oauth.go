package zoom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (c *Client) addRequestOAuth(req *http.Request, err error) (*http.Request, error) {
	if err != nil {
		return nil, err
	}

	url := "https://zoom.us/oauth/token?grant_type=client_credentials"

	req, errAuth := http.NewRequest("POST", url, bytes.NewBuffer([]byte{}))
	if errAuth != nil {
		return nil, errAuth
	}

	req.SetBasicAuth(c.Key, c.Secret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	var accessTokenResp AccessTokenResponse
	err = json.Unmarshal(body, &accessTokenResp)
	if err != nil {
		return nil, err
	}

	// set OAuth Authorization header
	req.Header.Add("Authorization", "Bearer "+accessTokenResp.AccessToken)

	return req, nil
}
