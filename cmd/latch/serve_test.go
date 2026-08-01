package main

import "testing"

func TestLoopbackListen(t *testing.T) {
	for _, address := range []string{"127.0.0.1:7070", "[::1]:7070", "localhost:7070"} {
		if !loopbackListen(address) {
			t.Errorf("%q should be loopback", address)
		}
	}
	for _, address := range []string{"0.0.0.0:7070", ":7070", "192.0.2.1:7070", "invalid"} {
		if loopbackListen(address) {
			t.Errorf("%q should not be loopback", address)
		}
	}
}

func TestValidateServeSecurity(t *testing.T) {
	if err := validateServeSecurity("127.0.0.1:7070", "", "", "", "", false); err != nil {
		t.Fatal(err)
	}
	if err := validateServeSecurity("127.0.0.1:7070", "agent", "", "", "", false); err == nil {
		t.Fatal("trusted loopback identity must require authentication")
	}
	if err := validateServeSecurity("0.0.0.0:7070", "agent", "token", "", "", false); err == nil {
		t.Fatal("remote cleartext listener was accepted")
	}
	if err := validateServeSecurity("0.0.0.0:7070", "agent", "token", "", "", true); err != nil {
		t.Fatal(err)
	}
	if err := validateServeSecurity("0.0.0.0:7070", "agent", "token", "cert.pem", "key.pem", false); err != nil {
		t.Fatal(err)
	}
}
