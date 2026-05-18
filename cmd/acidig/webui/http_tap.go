package webui

import (
	"net/http"
	"net/http/httputil"
)

// httpTap is an http.RoundTripper that captures the dump of each HTTP
// request and response as it passes through. Used by the DoH transport
// in webui so the UI can show the actual HTTP envelope (method, URL,
// headers, status) alongside the DNS payload.
//
// Bodies are intentionally excluded from both dumps: the DoH request
// body is the wire-encoded DNS query and the response body is the
// wire-encoded DNS reply — both are already captured by tapExchanger
// and rendered as the structured DNS message + hex view, so dumping
// them again as part of the HTTP envelope would be noise.
type httpTap struct {
	rt           http.RoundTripper
	requestText  string
	responseText string
}

func newHTTPTap(rt http.RoundTripper) *httpTap {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &httpTap{rt: rt}
}

func (t *httpTap) RoundTrip(req *http.Request) (*http.Response, error) {
	if dump, err := httputil.DumpRequestOut(req, false); err == nil {
		t.requestText = string(dump)
	}
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	if dump, derr := httputil.DumpResponse(resp, false); derr == nil {
		t.responseText = string(dump)
	}
	return resp, nil
}
