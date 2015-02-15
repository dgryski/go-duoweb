package duoweb

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	Host string
	Key  string
	IKey string
}

const (
	apiprefix = "/auth/v2"
)

func NewClient(host, key, ikey string) *Client {
	return &Client{
		Host: strings.ToLower(host),
		Key:  key,
		IKey: ikey,
	}

}

type PingResponse struct {
	Response struct {
		Time int `json:"time"`
	} `json:"response"`
	Stat string `json:"stat"`
}

func (c *Client) Ping() (PingResponse, error) {

	resp, err := http.Get("https://" + c.Host + apiprefix + "/ping")
	if err != nil {
		return PingResponse{}, err
	}
	defer resp.Body.Close()

	var js PingResponse

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&js)
	return js, err
}

func (c *Client) Check() (PingResponse, error) {

	path := apiprefix + "/check"

	req, err := http.NewRequest("GET", "https://"+c.Host+path, nil)
	if err != nil {
		return PingResponse{}, err
	}

	now := timeNow().Format(time.RFC1123Z)

	req.Header.Add("Date", now)
	req.Header.Add("Authorization", "Basic "+c.sign("GET", now, path, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return PingResponse{}, err
	}
	defer resp.Body.Close()

	var js PingResponse

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&js)
	return js, err
}

func (c *Client) AuthPush(userid string) (map[string]interface{}, error) {

	path := apiprefix + "/auth"

	req, err := http.NewRequest("POST", "https://"+c.Host+path, nil)
	if err != nil {
		return nil, err
	}

	params := url.Values{"user_id": []string{userid}, "factor": []string{"push"}, "device": []string{"auto"}}
	req.URL.RawQuery = params.Encode()

	now := timeNow().Format(time.RFC1123Z)

	req.Header.Add("Date", now)
	req.Header.Add("Authorization", "Basic "+c.sign("POST", now, path, params))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	js := make(map[string]interface{})

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&js)
	return js, err
}

func (c *Client) AuthPasscode(userid, passcode string) (map[string]interface{}, error) {

	path := apiprefix + "/auth"

	req, err := http.NewRequest("POST", "https://"+c.Host+path, nil)
	if err != nil {
		return nil, err
	}

	params := url.Values{"user_id": []string{userid}, "factor": []string{"passcode"}, "passcode": []string{passcode}}
	req.URL.RawQuery = params.Encode()

	now := timeNow().Format(time.RFC1123Z)

	req.Header.Add("Date", now)
	req.Header.Add("Authorization", "Basic "+c.sign("POST", now, path, params))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	js := make(map[string]interface{})

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&js)
	return js, err
}

func (c *Client) sign(date, method, path string, params url.Values) string {

	body := []string{method, date, c.Host, path, ""}
	if params != nil {
		s := params.Encode()
		s = strings.Replace(s, "+", "%20", -1)
		body[4] = s
	}

	canon := strings.Join(body, "\n")

	h := hmac.New(sha1.New, []byte(c.Key))
	h.Write([]byte(canon))

	src := make([]byte, sha1.Size)
	dst := make([]byte, hex.EncodedLen(len(src)))

	hex.Encode(dst, h.Sum(src[:0]))

	auth := fmt.Sprintf("%s:%s", c.IKey, dst)

	return base64.StdEncoding.EncodeToString([]byte(auth))
}
