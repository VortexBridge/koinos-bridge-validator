package rpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBoundedKoinosTransportRejectsRedirectsAndNonReadCalls(t *testing.T) {
	var received int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&received, 1); w.Write([]byte(`{}`)) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	rpc := NewBoundedJsonRPC(source.URL + "/synthetic-private-credential")
	if _, err := rpc.GetChainID(context.Background()); err == nil || strings.Contains(err.Error(), "synthetic-private-credential") {
		t.Fatal("redirect accepted or endpoint leaked", err)
	}
	if atomic.LoadInt32(&received) != 0 {
		t.Fatal("followed redirect")
	}
	if _, err := rpc.ApplyBlock(context.Background(), nil); err == nil {
		t.Fatal("submitted through read-only transport")
	}
}

func TestBoundedKoinosTransportRejectsMalformedIdentityResponses(t *testing.T) {
	for _, response := range []string{
		`{"id":2,"result":{"chain_id":"EiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}`,
		`{"id":1,"result":null}`,
		`{"id":1,"error":{"message":"synthetic-private-credential"}}`,
		`{"id":1,"result":{"chain_id":"bad-encoding"}}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(response)) }))
		_, err := NewBoundedJsonRPC(server.URL).GetChainID(context.Background())
		server.Close()
		if err == nil || strings.Contains(err.Error(), "synthetic-private-credential") {
			t.Fatal("invalid response accepted or upstream error leaked", err)
		}
	}
}
