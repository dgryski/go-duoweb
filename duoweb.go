package duoweb

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

const duoPrefix = "TX"
const appPrefix = "APP"
const authPrefix = "AUTH"

const duoExpire = 300
const appExpire = 3600

const ikeyLen = 20
const skeyLen = 40
const akeyLen = 40

var ErrUSER = errors.New("ERR|The username passed to sign_request() is invalid.")
var ErrIKEY = errors.New("ERR|The Duo integration key passed to sign_request() is invalid.")
var ErrSKEY = errors.New("ERR|The Duo secret key passed to sign_request() is invalid.")
var ErrAKEY = errors.New("ERR|The application secret key passed to sign_request() must be at least 40 characters.")
var ErrUnknown = errors.New("ERR|An unknown error has occurred.")

// for mocking during tests
var timeNow = time.Now

func signVals(key, username, ikey, prefix string, expire int) string {

	exp := timeNow().Add(time.Duration(expire) * time.Second)

	val := username + "|" + ikey + "|" + strconv.Itoa(int(exp.Unix()))
	cookie := prefix + "|" + base64.StdEncoding.EncodeToString([]byte(val))
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(cookie))
	sig := h.Sum(nil)
	return cookie + "|" + hex.EncodeToString(sig)
}

func parseVals(key, val, prefix string) string {

	ts := int(timeNow().Unix())

	parts := strings.Split(val, "|")

	if len(parts) != 3 {
		return ""
	}

	vprefix, vb64, vsig := parts[0], parts[1], parts[2]

	h := hmac.New(sha1.New, []byte(key))

	h.Write([]byte(vprefix + "|" + vb64))

	sig := h.Sum(nil)
	bsig, err := hex.DecodeString(vsig)
	if err != nil || len(bsig) != len(sig) {
		return ""
	}

	// The reference implementations all compare hmac_sha1(sig, key) with
	// hmac_sha1(bsig, key) to get around the lack of constant-time
	// compares in the different languages.
	if !hmac.Equal(sig, bsig) {
		return ""
	}

	if prefix != vprefix {
		return ""
	}

	decoded, err := base64.StdEncoding.DecodeString(vb64)
	if err != nil {
		return ""
	}

	cookie_parts := strings.Split(string(decoded), "|")

	username, _ /* ikey */, expire := cookie_parts[0], cookie_parts[1], cookie_parts[2]

	expire_ts, err := strconv.Atoi(expire)
	if err != nil {
		return ""
	}

	if ts >= expire_ts {
		return ""
	}

	return username
}

func SignRequest(ikey, skey, akey, username string) (string, error) {
	if username == "" {
		return "", ErrUSER
	}

	if ikey == "" || len(ikey) != ikeyLen {
		return "", ErrIKEY
	}

	if skey == "" || len(skey) != skeyLen {
		return "", ErrSKEY
	}

	if akey == "" || len(akey) < akeyLen {
		return "", ErrAKEY
	}

	duoSig := signVals(skey, username, ikey, duoPrefix, duoExpire)
	appSig := signVals(akey, username, ikey, appPrefix, appExpire)

	return duoSig + ":" + appSig, nil
}

func VerifyResponse(ikey, skey, akey, response string) string {

	sigs := strings.Split(response, ":")
	if len(sigs) != 2 {
		return ""
	}

	authSig, appSig := sigs[0], sigs[1]

	authUser := parseVals(skey, authSig, authPrefix)

	appUser := parseVals(akey, appSig, appPrefix)

	if authUser == "" || appUser == "" || authUser != appUser {
		return ""
	}

	return authUser
}
