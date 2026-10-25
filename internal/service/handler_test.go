package service

import (
	"net/http/httptest"
	"testing"
)

func TestHTTPContract(t *testing.T) {
	handler := Handler()
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/healthz", "ok\n", 200}, {"GET", "/readyz", "ready\n", 200},
		{"GET", "/version", "{\"service\":\"supply-demo\",\"api\":1}\n", 200},
		{"HEAD", "/healthz", "", 200}, {"POST", "/healthz", "", 405},
		{"GET", "/missing", "404 page not found\n", 404},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://example.test"+tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status || w.Body.String() != tc.body {
				t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}
