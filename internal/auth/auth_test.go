package auth

import (
	"net/http"
	"testing"
)

func TestNoAuthHeader(t *testing.T) {
	headers := http.Header{
		"Host":         {"www.host.com"},
		"Content-Type": {"application/json"},
	}

	_, err := GetAPIKey(headers)
	expected := "no authorization header included"

	if err.Error() != expected {
		t.Error("The wrong error was thrown")
	}
}

func TestWrongApiKey(t *testing.T) {
	headers := http.Header{
		"Host":          {"www.host.com"},
		"Content-Type":  {"application/json"},
		"Authorization": {"NotKey Token"},
	}

	_, err := GetAPIKey(headers)
	expected := "malformed authorization header"

	if err.Error() != expected {
		t.Error("The wrong error was thrown")
	}
}

func TestInvalidApiKey(t *testing.T) {
	headers := http.Header{
		"Host":          {"www.host.com"},
		"Content-Type":  {"application/json"},
		"Authorization": {"NotKey"},
	}

	_, err := GetAPIKey(headers)
	expected := "malformed authorization header"

	if err.Error() != expected {
		t.Error("The wrong error was thrown")
	}
}

func TestValidApiKey(t *testing.T) {
	headers := http.Header{
		"Host":          {"www.host.com"},
		"Content-Type":  {"application/json"},
		"Authorization": {"ApiKey Token"},
	}

	key, err := GetAPIKey(headers)

	if err != nil {
		t.Error("this should work, but doesn't")
	}

	if key != "Token" {
		t.Error("the wrong API Key was returned")
	}
}
