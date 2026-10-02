package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/lru"
)

/* try bytes cache*/
var Cache *lru.LRUCache[string, []byte]
var Queries int

type DNSHandler struct {
	DNSClient *fastdns.Client
	Debug     bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		slog.Info("serve dns request", "domain", string(req.Domain), "class", req.Question.Class, "type", req.Question.Type)
	}

	defer func() {
		if recoveryMessage := recover(); recoveryMessage != nil {
			slog.Error(fmt.Sprint(recoveryMessage), "stack", string(debug.Stack()))
			resp := fastdns.AcquireMessage()
			defer fastdns.ReleaseMessage(resp)
			fastdns.Error(rw, req, fastdns.RcodeServFail)
			_, _ = rw.Write(resp.Raw)
		}
	}()

	if req.Question.Type != fastdns.TypeA {
		switch req.Question.Type {
		case fastdns.TypeA:
			fastdns.HOST1(rw, req, 60, netip.AddrFrom4([4]byte{8, 8, 8, 8}))
		case fastdns.TypeAAAA:
			fastdns.HOST(rw, req, 60, []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")})
		case fastdns.TypeCNAME:
			fastdns.CNAME(rw, req, 60, []string{"dns.google"}, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
		case fastdns.TypeSRV:
			fastdns.SRV(rw, req, 60, []net.SRV{{"www.google.com", 443, 1000, 1000}})
		case fastdns.TypeNS:
			fastdns.NS(rw, req, 60, []net.NS{{"ns1.google.com"}, {"ns2.google.com"}})
		case fastdns.TypeMX:
			fastdns.MX(rw, req, 60, []net.MX{{"mail.gmail.com", 10}, {"smtp.gmail.com", 10}})
		case fastdns.TypeSOA:
			fastdns.SOA(rw, req, 60, net.NS{"ns1.google"}, net.NS{"ns2.google"}, 60, 90, 90, 180, 60)
		case fastdns.TypePTR:
			fastdns.PTR(rw, req, 0, "ptr.google.com")
		case fastdns.TypeTXT:
			fastdns.TXT(rw, req, 60, "greetingfromgoogle")
		default:
			fastdns.Error(rw, req, fastdns.RcodeNXDomain)
		}

		return
	}

	key := cacheKey(req)
	if cachedResp, ok := Cache.Get(key); ok {
		// cachedResp is shared with other concurrent requests for the
		// same key — copy before patching the per-request ID.
		out := make([]byte, len(cachedResp))
		copy(out, cachedResp)
		out[0] = uint8(req.Header.ID >> 8)
		out[1] = uint8(req.Header.ID)
		_, _ = rw.Write(out)
		return
	}

	resp := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(resp)

	ctx := context.Background()

	err := h.DNSClient.Exchange(ctx, req, resp)
	if err != nil {
		slog.Error("serve exchange dns request error", "error", err, "remote_addr", rw.RemoteAddr(), "domain", req.Domain, "class", req.Question.Class, "type", req.Question.Type)
		fastdns.Error(rw, req, fastdns.RcodeServFail)
	}

	// Cache a copy: resp.Raw is reused by the AcquireMessage pool after
	// ReleaseMessage, so storing it directly would corrupt the entry.
	cached := make([]byte, len(resp.Raw))
	copy(cached, resp.Raw)
	Cache.Set(key, cached)

	_, _ = rw.Write(resp.Raw)
}

// cacheKey namespaces cache entries by domain + qtype so different
// question types for the same name don't collide.
func cacheKey(req *fastdns.Message) string {
	return string(req.Domain) + "|" + strconv.Itoa(int(req.Question.Type))
}

func main() {
	addr := "127.0.0.1:5356"

	Raw := make([]byte, 4)
	ID := uint16(39424)
	Raw[0] = uint8(ID >> 8)
	Raw[1] = uint8(ID)

	slog.Error("Test", "r", fmt.Sprintf("%x", ID), "raw", fmt.Sprintf("%x", Raw[0]), "orig", fmt.Sprintf("%x", uint8(ID>>8)))

	ResID := uint16(Raw[0])<<8 | uint16(Raw[1])

	slog.Error("IDS", "orig", ID, "converted", ResID)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	Cache = lru.NewLRUCache[string, []byte](1000)

	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			DNSClient: &fastdns.Client{
				Addr:    "1.1.1.1:53",
				Timeout: 3 * time.Second,
			},
			Debug: false, //os.Getenv("DEBUG") != "",
		},
		Stats: &fastdns.CoreStats{
			Prefix: "coredns_",
			Family: "1",
			Proto:  "udp",
			Server: "dns://" + addr,
			Zone:   ".",
		},
		ErrorLog: slog.Default(),
		MaxProcs: 4,
	}
	slog.Error("MaxProc", "procs", server.MaxProcs)

	err := server.ListenAndServe(addr)
	if err != nil {
		slog.Error("dnsserver serve failed", "error", err)
	}
}
