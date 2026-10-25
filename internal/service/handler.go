package service

import "net/http"

// Handler exposes fixed responses and requires no filesystem writes or outbound traffic.
func Handler() http.Handler {
	mux := http.NewServeMux()
	for path, body := range map[string]string{"/healthz": "ok\n", "/readyz": "ready\n", "/version": "{\"service\":\"supply-demo\",\"api\":1}\n"} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			if path == "/version" {
				w.Header().Set("Content-Type", "application/json")
			} else {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			}
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(body))
			}
		})
	}
	return mux
}
