package main

import (
	"context"
	"log/slog"
	"os"
    "time"

	"github.com/phuslu/fastdns"
)

type DNSHandler struct {
	DNSClient *fastdns.Client
	Debug bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		slog.Info("serve dns request", "domain", req.Domain, "class", req.Question.Class, "type", req.Question.Type)
	}

	resp := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(resp)

	ctx := context.Background()

	err := h.DNSClient.Exchange(ctx, req, resp)
	if err != nil {
		slog.Error("serve exchange dns request error", "error", err, "remote_addr", rw.RemoteAddr(), "domain", req.Domain, "class", req.Question.Class, "type", req.Question.Type)
		fastdns.Error(rw, req, fastdns.RcodeServFail)
	}

    _, _ = rw.Write(resp.Raw)
}

func main() {
	addr := "127.0.0.1:53"

	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			DNSClient: &fastdns.Client{
				Addr:    "1.1.1.1:53",
				Timeout: 3 * time.Second,
			},
			Debug: os.Getenv("DEBUG") != "",
		},
		Stats: &fastdns.CoreStats{
			Prefix: "coredns_",
			Family: "1",
			Proto:  "udp",
			Server: "dns://" + addr,
			Zone:   ".",
		},
		ErrorLog: slog.Default(),
	}

	err := server.ListenAndServe(addr)
	if err != nil {
		slog.Error("dnsserver serve failed", "error", err)
	}
}
