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

type prefix string

const (
	duoPrefix           prefix = "TX"
	appPrefix                  = "APP"
	authPrefix                 = "AUTH"
	enrollPrefix               = "ENROLL"
	enrollRequestPrefix        = "ENROLL_REQUEST"
)

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

func signVals(key, username, ikey string, reqPrefix prefix, expire int) string {

	exp := timeNow().Add(time.Duration(expire) * time.Second)

	val := username + "|" + ikey + "|" + strconv.Itoa(int(exp.Unix()))
	cookie := string(reqPrefix) + "|" + base64.StdEncoding.EncodeToString([]byte(val))
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(cookie))
	sig := h.Sum(nil)
	return cookie + "|" + hex.EncodeToString(sig)
}

func parseVals(key, val string, reqPrefix prefix) string {

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

	if string(reqPrefix) != vprefix {
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

func SignRequest(ikey, skey, akey string, username string) (string, error) {
	return signRequest(ikey, skey, akey, duoPrefix, username)
}

func SignEnrollRequest(ikey, skey, akey string, username string) (string, error) {
	return signRequest(ikey, skey, akey, enrollRequestPrefix, username)
}

func signRequest(ikey, skey, akey string, reqPrefix prefix, username string) (string, error) {

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

	duoSig := signVals(skey, username, ikey, reqPrefix, duoExpire)
	appSig := signVals(akey, username, ikey, appPrefix, appExpire)

	return duoSig + ":" + appSig, nil
}

func VerifyResponse(ikey, skey, akey, response string) string {
	return verifyResponse(ikey, skey, akey, response, authPrefix)
}

func VerifyEnrollResponse(ikey, skey, akey, response string) string {
	return verifyResponse(ikey, skey, akey, response, enrollRequestPrefix)
}

func verifyResponse(ikey, skey, akey, response string, reqPrefix prefix) string {

	sigs := strings.Split(response, ":")
	if len(sigs) != 2 {
		return ""
	}

	authSig, appSig := sigs[0], sigs[1]

	user := parseVals(skey, authSig, reqPrefix)

	appUser := parseVals(akey, appSig, appPrefix)

	if user == "" || appUser == "" || user != appUser {
		return ""
	}

	return user
}
