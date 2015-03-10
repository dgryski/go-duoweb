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
	"strconv"
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
	if e.MessageDetail != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.MessageDetail)
	}
	return e.Message
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

	var js PingResponse
	err := c.sendRequest("GET", path, nil, &js)
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

func (c *Client) sendRequest(method, path string, params url.Values, response interface{}) error {

	req, err := http.NewRequest(method, "https://"+c.Host+path, nil)
	if err != nil {
		return err
	}

	req.URL.RawQuery = params.Encode()

	now := timeNow().Format(time.RFC1123Z)

	req.Header.Add("Date", now)
	req.Header.Add("Authorization", "Basic "+c.sign(method, now, path, params))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	err = unpackResponse(resp.Body, response)
	return err
}

type AuthResponse struct {
	Result    string `mapstructure:"result"`
	Status    string `mapstructure:"status"`
	StatusMsg string `mapstructure:"status_msg"`
	Txid      string `mapstsructure:"txid"`
}

func (c *Client) AuthPush(userid string, async bool) (AuthResponse, error) {

	path := apiprefix + "/auth"
	params := url.Values{"user_id": []string{userid}, "factor": []string{"push"}, "device": []string{"auto"}}

	if async {
		params["async"] = []string{"1"}
	}

	var r AuthResponse
	err := c.sendRequest("POST", path, params, &r)
	return r, err
}

func (c *Client) AuthPasscode(userid, passcode string, async bool) (AuthResponse, error) {

	path := apiprefix + "/auth"
	params := url.Values{"user_id": []string{userid}, "factor": []string{"passcode"}, "passcode": []string{passcode}}

	if async {
		params["async"] = []string{"1"}
	}

	var r AuthResponse
	err := c.sendRequest("POST", path, params, &r)
	return r, err
}

func (c *Client) PollAuthStatus(txid string) (AuthResponse, error) {

	path := apiprefix + "/auth_status"

	params := url.Values{"txid": []string{txid}}

	var r AuthResponse
	err := c.sendRequest("GET", path, params, &r)
	return r, err
}

type EnrollResponse struct {
	ActivationBarcode string `mapstructure:"activation_barcode"`
	ActivationCode    string `mapstructure:"activation_code"`
	Expiration        int    `mapstructure:"expiration"`
	UserId            string `mapstructure:"user_id"`
	Username          string `mapstructure:"username"`
}

func (c *Client) Enroll(username string, validSeconds int) (EnrollResponse, error) {

	path := apiprefix + "/enroll"

	params := url.Values{}

	if username != "" {
		params["username"] = []string{username}
	}

	if validSeconds != 0 {
		params["valid_secs"] = []string{strconv.Itoa(validSeconds)}
	}

	var r EnrollResponse
	err := c.sendRequest("POST", path, params, &r)
	return r, err
}

type EnrollStatusResponse string

func (c *Client) PollEnrollStatus(userid, activationCode string) (EnrollStatusResponse, error) {

	path := apiprefix + "/enroll_status"

	params := url.Values{"user_id": []string{userid}, "activation_code": []string{activationCode}}

	var r EnrollStatusResponse
	err := c.sendRequest("POST", path, params, &r)
	return r, err
}

type PreauthResponse struct {
	Result    string `mapstructure:"result"`
	StatusMsg string `mapstructure:"status_msg"`
	Devices   []struct {
		Device       string   `mapstructure:"device"`
		Type         string   `mapstructure:"type"`
		Number       string   `mapstructure:"number"`
		Name         string   `mapstructure:"name"`
		Capabilities []string `mapstructure:"capabilities"`
	} `mapstructure:"devices"`
	EnrollPortalUrl string `mapstructure:"enroll_portal_url"`
}

func (c *Client) Preauth(userid string) (PreauthResponse, error) {

	path := apiprefix + "/preauth"

	params := url.Values{"user_id": []string{userid}}

	var r PreauthResponse
	err := c.sendRequest("POST", path, params, &r)
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
