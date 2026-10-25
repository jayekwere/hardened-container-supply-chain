package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jayekwere/hardened-container-supply-chain/internal/service"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--check-runtime" {
		if err := service.CheckRuntime(); err != nil {
			log.Fatal(err)
		}
		log.Print("runtime: uid=65532, rootfs=read-only, capabilities=0, no-new-privileges=1")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	s := &http.Server{Addr: ":8080", Handler: service.Handler(), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdown); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Print("listening on :8080")
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
