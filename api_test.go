package duoweb

import (
	"net/url"
	"testing"
)

func TestSignHeaders(t *testing.T) {

	method := "POST"
	date := "Tue, 21 Aug 2012 17:29:18 -0000"
	path := "/accounts/v1/account/list"

	params := url.Values{
		"realname": []string{"First Last"},
		"username": []string{"root"},
	}

	c := NewClient(
		"api-XXXXXXXX.duosecurity.com",
		"Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep",
		"DIWJ8X6AEYOR5OMC6TQ1",
	)

	got := c.sign(method, date, path, params)

	want := "RElXSjhYNkFFWU9SNU9NQzZUUTE6MmQ5N2Q2MTY2MzE5NzgxYjVhM2EwN2FmMzlkMzY2ZjQ5MTIzNGVkYw=="

	if got != want {
		t.Errorf("c.sign(...)=%v, want %v", got, want)
	}

}
