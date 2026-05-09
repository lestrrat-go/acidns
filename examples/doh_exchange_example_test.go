package examples_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

func Example_doh_exchange() {
	// Stand up a TLS HTTP server that speaks RFC 8484: read the wire
	// query out of the POST body, return a wire response with a fixed
	// A record.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := wire.Unmarshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, _ := wire.NewBuilder().
			ID(req.ID()).Response(true).
			Question(req.Questions()[0]).
			Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
				rdata.MustNewA(netip.MustParseAddr("198.51.100.99")))).
			Build()
		out, _ := wire.Marshal(resp)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	defer srv.Close()

	// httptest.NewTLSServer hands us a Client wired to trust its self-
	// signed cert; pipe that through to the DoH exchanger.
	ex, err := doh.New(srv.URL+"/dns-query", doh.WithHTTPClient(srv.Client()))
	if err != nil {
		fmt.Println("doh:", err)
		return
	}

	q, _ := wire.NewBuilder().
		ID(0x55aa).RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := ex.Exchange(ctx, q)
	if err != nil {
		fmt.Println("exchange:", err)
		return
	}
	if a, ok := wire.RDataAs[rdata.A](resp.Answers()[0]); ok {
		fmt.Println("doh answer:", a.Addr())
	}

	// OUTPUT:
	// doh answer: 198.51.100.99
}
