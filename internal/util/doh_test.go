package util

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupTXTDOH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "example.com" || r.URL.Query().Get("type") != "TXT" {
			t.Errorf("unexpected query: %v", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = w.Write(
			[]byte(
				`{"Status":0,"Answer":[{"name":"example.com","type":16,"TTL":60,"data":"\"tok123\""}]}`,
			),
		)
	}))
	defer srv.Close()

	got, err := LookupTXTDOH(context.Background(), "example.com", srv.URL)
	if err != nil {
		t.Fatalf("LookupTXTDOH: %v", err)
	}
	if len(got) != 1 || got[0] != "tok123" {
		t.Fatalf("want [tok123], got %v", got)
	}
}

func TestLookupTXTDOHMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Status":0,"Answer":[]}`))
	}))
	defer srv.Close()

	got, err := LookupTXTDOH(context.Background(), "example.com", srv.URL)
	if err != nil {
		t.Fatalf("LookupTXTDOH: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}
