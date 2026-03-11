package main

import "testing"

func TestReadInputArgs(t *testing.T) {
	got, err := readInput(false, []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "echo hello" {
		t.Fatalf("got %q", got)
	}
}
