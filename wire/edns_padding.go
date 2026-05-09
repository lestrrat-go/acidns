package wire

// paddingBlock is the recommended client block size from RFC 8467 §4.1.
const paddingBlock = 128

// PadEncrypted returns a copy of m with an EDNS Padding option (RFC 7830)
// sized so the on-wire serialised length is a multiple of 128 octets per
// the RFC 8467 §4.1 "block-length-padding" client recommendation. If m
// already carries a Padding option PadEncrypted returns m unchanged;
// otherwise an OPT pseudo-RR is added (or extended) with the right
// number of zero padding bytes.
//
// PadEncrypted is intended for clients sending queries over encrypted
// transports (DoT, DoH, DoQ). The dot, doh, and doq packages call it
// automatically; callers building messages for non-encrypted transports
// SHOULD NOT pad — RFC 8467 §6 explicitly recommends against padding on
// the unencrypted UDP/TCP path.
//
// On any internal failure (Build / Marshal error) the original m is
// returned unchanged so callers do not have to handle a second error
// path on the hot send path.
func PadEncrypted(m Message) Message {
	var existing []EDNSOption
	udpSize := uint16(1232)
	extRCODE := uint8(0)
	version := uint8(0)
	do := false
	if e, ok := m.EDNS(); ok {
		for _, opt := range e.Options() {
			if opt.Code() == EDNSOptionPadding {
				return m
			}
		}
		existing = e.Options()
		udpSize = e.UDPSize()
		extRCODE = e.ExtendedRCODE()
		version = e.Version()
		do = e.DO()
	}

	build := func(padBytes int) (Message, []byte, error) {
		eb := NewEDNSBuilder().
			UDPSize(udpSize).
			ExtendedRCODE(extRCODE).
			Version(version).
			DO(do)
		for _, o := range existing {
			eb = eb.Option(o)
		}
		pad, err := NewEDNSOption(EDNSOptionPadding, make([]byte, padBytes))
		if err != nil {
			return Message{}, nil, err
		}
		eb = eb.Option(pad)

		b := NewMessageBuilder().ID(m.ID()).Flags(m.Flags())
		for _, q := range m.Questions() {
			b = b.Question(q)
		}
		for _, r := range m.Answers() {
			b = b.Answer(r)
		}
		for _, r := range m.Authorities() {
			b = b.Authority(r)
		}
		for _, r := range m.Additionals() {
			b = b.Additional(r)
		}
		ed, err := eb.Build()
		if err != nil {
			return Message{}, nil, err
		}
		b = b.EDNS(ed)

		msg, err := b.Build()
		if err != nil {
			return Message{}, nil, err
		}
		buf, err := Marshal(msg)
		if err != nil {
			return Message{}, nil, err
		}
		return msg, buf, nil
	}

	_, buf0, err := build(0)
	if err != nil {
		return m
	}
	rem := len(buf0) % paddingBlock
	if rem == 0 {
		// Empty Padding option already aligns the message; rebuild once
		// more to drop any temporary state and return.
		msg, _, err := build(0)
		if err != nil {
			return m
		}
		return msg
	}
	msg, _, err := build(paddingBlock - rem)
	if err != nil {
		return m
	}
	return msg
}
