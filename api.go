package duoweb

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
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

type Error struct {
	Stat          string `mapstructure:"stat"`
	Code          int    `mapstructure:"code"`
	Message       string `mapstructure:"message"`
	MessageDetail string `mapstructure:"message_detail"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Message, e.MessageDetail)
}

type PingResponse struct {
	Time int
}

func (c *Client) Ping() (PingResponse, error) {

	resp, err := http.Get("https://" + c.Host + apiprefix + "/ping")
	if err != nil {
		return PingResponse{}, err
	}
	defer resp.Body.Close()

	var js PingResponse
	err = unpackResponse(resp.Body, &js)
	return js, err
}

func (c *Client) Check() (PingResponse, error) {

	path := apiprefix + "/check"

	resp, err := c.sendRequest("GET", path, nil)
	if err != nil {
		return PingResponse{}, err
	}
	defer resp.Body.Close()

	var js PingResponse
	err = unpackResponse(resp.Body, &js)
	return js, err

}

func unpackResponse(r io.Reader, dst interface{}) error {

	var m map[string]interface{}

	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return err
	}

	if m["stat"] == "FAIL" {
		var e Error
		mapstructure.Decode(m, &e)
		return &e
	}

	return mapstructure.Decode(m["response"], dst)
}

func (c *Client) sendRequest(method, path string, params url.Values) (*http.Response, error) {

	req, err := http.NewRequest(method, "https://"+c.Host+path, nil)
	if err != nil {
		return nil, err
	}

	req.URL.RawQuery = params.Encode()

	now := timeNow().Format(time.RFC1123Z)

	req.Header.Add("Date", now)
	req.Header.Add("Authorization", "Basic "+c.sign(method, now, path, params))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type AuthResponse struct {
	Result    string `mapstructure:"result"`
	Status    string `mapstructure:"status"`
	StatusMsg string `mapstructure:"status_msg"`
}

func (c *Client) AuthPush(userid string) (AuthResponse, error) {

	path := apiprefix + "/auth"
	params := url.Values{"user_id": []string{userid}, "factor": []string{"push"}, "device": []string{"auto"}}

	resp, err := c.sendRequest("POST", path, params)
	if err != nil {
		return AuthResponse{}, err
	}
	defer resp.Body.Close()

	var r AuthResponse
	err = unpackResponse(resp.Body, &r)
	return r, err
}

func (c *Client) AuthPasscode(userid, passcode string) (AuthResponse, error) {

	path := apiprefix + "/auth"
	params := url.Values{"user_id": []string{userid}, "factor": []string{"passcode"}, "passcode": []string{passcode}}

	resp, err := c.sendRequest("POST", path, params)
	if err != nil {
		return AuthResponse{}, err
	}
	defer resp.Body.Close()

	var r AuthResponse
	err = unpackResponse(resp.Body, &r)
	return r, err
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
