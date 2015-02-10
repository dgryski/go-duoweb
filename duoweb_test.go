package duoweb

import (
	"strings"
	"testing"
)

const (
	dummyIKEY     = "DIXXXXXXXXXXXXXXXXXX"
	wrongIKEY     = "DIXXXXXXXXXXXXXXXXXY"
	dummySKEY     = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	dummyAKEY     = "useacustomerprovidedapplicationsecretkey"
	dummyUsername = "testuser"
)

func TestSignRequest(t *testing.T) {

	rsig, err := SignRequest(dummyIKEY, dummySKEY, dummyAKEY, dummyUsername)

	if rsig == "" || err != nil {
		t.Error("valid signRequest failed: err=", err)
	}

	rsig, err = SignRequest(dummyIKEY, dummySKEY, dummyAKEY, "")
	if rsig != "" || err != ErrUSER {
		t.Error("bad user signRequest test failed: rsig=", rsig, "err=", err)
	}

	rsig, err = SignRequest(dummyIKEY, dummySKEY, dummyAKEY, "in|valid")
	if rsig != "" || err != ErrUSER {
		t.Error("bad user signRequest test failed: rsig=", rsig, "err=", err)
	}

	rsig, err = SignRequest("invalid", dummySKEY, dummyAKEY, dummyUsername)
	if rsig != "" || err != ErrIKEY {
		t.Error("bad ikey signRequest test failed: rsig=", rsig, "err=", err)
	}

	rsig, err = SignRequest(dummyIKEY, "invalid", dummyAKEY, dummyUsername)
	if rsig != "" || err != ErrSKEY {
		t.Error("bad skey signRequest test failed: rsig=", rsig, "err=", err)
	}

	rsig, err = SignRequest(dummyIKEY, dummySKEY, "invalid", dummyUsername)
	if rsig != "" || err != ErrAKEY {
		t.Error("bad akey signRequest test failed: rsig=", rsig, "err=", err)
	}
}

func TestVerifyResponse(t *testing.T) {

	const invalidResponse = "AUTH|INVALID|SIG"
	const expiredReponse = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702"
	const futureResponse = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef"

	const wrongParamsResponse = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|6cdbec0fbfa0d3f335c76b0786a4a18eac6cdca7"
	const wrongParamsApp = "APP|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|7c2065ea122d028b03ef0295a4b4c5521823b9b5"

	requestSig, _ := SignRequest(dummyIKEY, dummySKEY, dummyAKEY, dummyUsername)
	sigs := strings.Split(requestSig, ":")
	validAppSig := sigs[1]

	requestSig, _ = SignRequest(dummyIKEY, dummySKEY, "invalidinvalidinvalidinvalidinvalidinvalid", dummyUsername)
	sigs = strings.Split(requestSig, ":")
	invalidAppSig := sigs[1]

	var tests = []struct {
		response string
		output   string
		what     string
	}{
		{invalidResponse + ":" + validAppSig, "", "invalid user"},
		{expiredReponse + ":" + validAppSig, "", "expired user"},
		{futureResponse + ":" + validAppSig, dummyUsername, "future user"},
		{futureResponse + ":" + invalidAppSig, "", "future user -- invalid sig"},
		{futureResponse + ":" + wrongParamsApp, "", "verify_response - Future user, invalid app sig format"},
		{wrongParamsResponse + ":" + validAppSig, "", "verify_response - Invalid response format"},
	}

	for _, tt := range tests {
		r := VerifyResponse(dummyIKEY, dummySKEY, dummyAKEY, tt.response)
		if r != tt.output {
			t.Errorf("verify test for %s failed: got %s expected %s\n", tt.what, r, tt.output)
		}
	}

	if r := VerifyResponse(wrongIKEY, dummySKEY, dummyAKEY, futureResponse+":"+validAppSig); r != "" {
		t.Errorf("verify test for wrongIKEY failed: got %s expected \"\"", r)
	}
}
