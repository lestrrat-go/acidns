package tsig_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyResponseRoundTrip(t *testing.T) {
	t.Parallel()
	key := tsig.MustNewKey(wire.MustParseName("test.key"), tsig.HMACSHA256, mkSecret(t, 32))
	now := time.Now().Truncate(time.Second)

	// 1. Client signs the request and remembers its MAC.
	req := mkMessage(t)
	signedReq, err := tsig.Sign(req, key, now, 5*time.Minute)
	require.NoError(t, err)

	// 2. Server verifies the request, recovering the request MAC.
	_, requestMAC, _, err := tsig.VerifyMAC(signedReq, key, now, 5*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, requestMAC)

	// 3. Server signs the response, binding to the request MAC.
	resp := mkMessage(t)
	signedResp, err := tsig.SignResponse(resp, key, requestMAC, now, 5*time.Minute)
	require.NoError(t, err)

	// 4. Client verifies the response with the same request MAC.
	_, _, _, err = tsig.VerifyResponse(signedResp, key, requestMAC, now, 5*time.Minute) //nolint:dogsled // 4-tuple API
	require.NoError(t, err)
}

func TestVerifyResponseRejectsWithWrongRequestMAC(t *testing.T) {
	t.Parallel()
	key := tsig.MustNewKey(wire.MustParseName("test.key"), tsig.HMACSHA256, mkSecret(t, 32))
	now := time.Now().Truncate(time.Second)

	// Server signs a response bound to one request.
	signedReqA, err := tsig.Sign(mkMessage(t), key, now, 5*time.Minute)
	require.NoError(t, err)
	_, macA, _, err := tsig.VerifyMAC(signedReqA, key, now, 5*time.Minute)
	require.NoError(t, err)

	signedRespA, err := tsig.SignResponse(mkMessage(t), key, macA, now, 5*time.Minute)
	require.NoError(t, err)

	// A different request would produce a different MAC.
	signedReqB, err := tsig.Sign(mkMessage(t), key, now.Add(time.Second), 5*time.Minute)
	require.NoError(t, err)
	_, macB, _, err := tsig.VerifyMAC(signedReqB, key, now.Add(time.Second), 5*time.Minute)
	require.NoError(t, err)
	require.NotEqual(t, macA, macB)

	// Verifying response A under MAC B must fail — the binding
	// prevents replaying response A against request B.
	_, _, _, err = tsig.VerifyResponse(signedRespA, key, macB, now, 5*time.Minute) //nolint:dogsled // 4-tuple API
	require.ErrorIs(t, err, tsig.ErrBadSignature)
}

func TestSignVerifyAXFRChunkChain(t *testing.T) {
	t.Parallel()
	key := tsig.MustNewKey(wire.MustParseName("test.key"), tsig.HMACSHA256, mkSecret(t, 32))
	now := time.Now().Truncate(time.Second)

	// Establish initial MAC via request → first envelope (signed as response).
	req := mkMessage(t)
	signedReq, err := tsig.Sign(req, key, now, 5*time.Minute)
	require.NoError(t, err)
	_, reqMAC, _, err := tsig.VerifyMAC(signedReq, key, now, 5*time.Minute)
	require.NoError(t, err)

	first, err := tsig.SignResponse(mkMessage(t), key, reqMAC, now, 5*time.Minute)
	require.NoError(t, err)
	_, prevMAC, _, err := tsig.VerifyResponse(first, key, reqMAC, now, 5*time.Minute)
	require.NoError(t, err)

	// Sign a chained chunk (e.g. envelope #2 of an AXFR). prevMAC threads through.
	chunk, chunkMAC, err := tsig.SignAXFRChunk(mkMessage(t), key, prevMAC, now, 5*time.Minute)
	require.NoError(t, err)

	// Verify chunk with the same prevMAC.
	_, returnedMAC, _, err := tsig.VerifyAXFRChunk(chunk, key, prevMAC, now, 5*time.Minute)
	require.NoError(t, err)
	require.Equal(t, chunkMAC, returnedMAC,
		"VerifyAXFRChunk MAC must match the one returned by SignAXFRChunk")

	// Verifying with the wrong prevMAC must fail.
	_, _, _, err = tsig.VerifyAXFRChunk(chunk, key, reqMAC, now, 5*time.Minute) //nolint:dogsled // 4-tuple API
	require.ErrorIs(t, err, tsig.ErrBadSignature,
		"chained MAC must not verify under a different prior MAC")
}
