package validatorbb

import (
	"bytes"
	"strings"

	"github.com/lestrrat-go/acidns/wire"
)

// NameSuffixEqualOrSubdomain reports whether sub equals parent or is a
// strict subdomain of parent. The root name covers everything.
//
// Comparison is case-insensitive on the presentation form. acidns stores
// names lowercase already, so this also matches wire equality.
func NameSuffixEqualOrSubdomain(sub, parent wire.Name) bool {
	if sub.Equal(parent) {
		return true
	}
	subStr := strings.ToLower(sub.String())
	parentStr := strings.ToLower(parent.String())
	if parentStr == "." {
		return true
	}
	if !strings.HasSuffix(subStr, "."+parentStr) {
		return false
	}
	return true
}

// CanonicalNameCmp implements the RFC 4034 §6.1 canonical name ordering:
// label by label from the root, with bytes within each label compared
// lexicographically and "shorter prefix sorts before longer".
func CanonicalNameCmp(a, b wire.Name) int {
	aLabels := collectLabels(a)
	bLabels := collectLabels(b)
	n := min(len(bLabels), len(aLabels))
	for i := range n {
		if c := bytes.Compare(aLabels[i], bLabels[i]); c != 0 {
			return c
		}
	}
	return len(aLabels) - len(bLabels)
}

// collectLabels returns the labels of n in root-first order (the order in
// which they are compared by RFC 4034 §6.1). The returned slices are
// freshly allocated; names are stored lowercase already so no folding is
// required.
func collectLabels(n wire.Name) [][]byte {
	var leafFirst [][]byte
	for l := range n.Labels() {
		cp := make([]byte, len(l))
		copy(cp, l)
		leafFirst = append(leafFirst, cp)
	}
	for i, j := 0, len(leafFirst)-1; i < j; i, j = i+1, j-1 {
		leafFirst[i], leafFirst[j] = leafFirst[j], leafFirst[i]
	}
	return leafFirst
}

// NameCoveredBy reports whether qname falls strictly between owner and
// next in canonical DNS name order (RFC 4034 §6.1). Wraparound at the
// zone apex (next < owner) is handled per §4.1.1.
func NameCoveredBy(qname, owner, next wire.Name) bool {
	switch {
	case CanonicalNameCmp(owner, next) < 0:
		return CanonicalNameCmp(owner, qname) < 0 && CanonicalNameCmp(qname, next) < 0
	default:
		// Wraparound: qname > owner OR qname < next.
		return CanonicalNameCmp(owner, qname) < 0 || CanonicalNameCmp(qname, next) < 0
	}
}

// TruncateNameTo returns name with exactly k labels (counting from the
// root). If name has fewer than k labels, returns name unchanged. k=0
// returns the root name.
func TruncateNameTo(name wire.Name, k int) wire.Name {
	cur := name
	for cur.NumLabels() > k {
		parent, ok := cur.Parent()
		if !ok {
			break
		}
		cur = parent
	}
	return cur
}

// NextCloserName returns the name one label longer than encloser toward
// qname (RFC 5155 §1.3). For example, qname=a.b.c.example,
// encloser=c.example → next-closer = b.c.example.
func NextCloserName(qname, encloser wire.Name) wire.Name {
	cur := qname
	for cur.NumLabels() > encloser.NumLabels()+1 {
		parent, ok := cur.Parent()
		if !ok {
			return cur
		}
		cur = parent
	}
	return cur
}

// WildcardOf returns "*.<encloser>" — the wildcard owner name at encloser.
// Used by NSEC/NSEC3 wildcard-existence proofs.
func WildcardOf(encloser wire.Name) (wire.Name, error) {
	labels := []string{"*"}
	for l := range encloser.Labels() {
		labels = append(labels, string(l))
	}
	return wire.NameFromLabels(labels...)
}

// LongestCommonAncestor returns the deepest name that is an ancestor of
// (or equal to) both a and b. The root name covers everything, so this
// always returns at least a valid root. Used by the NSEC NXDOMAIN proof
// (RFC 4035 §5.4) to derive the closest encloser from a covering NSEC's
// owner and next field.
func LongestCommonAncestor(a, b wire.Name) wire.Name {
	aL := collectLabels(a)
	bL := collectLabels(b)
	n := min(len(aL), len(bL))
	matched := 0
	for matched < n && bytes.Equal(aL[matched], bL[matched]) {
		matched++
	}
	if matched == 0 {
		return rootName()
	}
	parts := make([]string, 0, matched)
	for i := matched - 1; i >= 0; i-- {
		parts = append(parts, string(aL[i]))
	}
	out, err := wire.NameFromLabels(parts...)
	if err != nil {
		return rootName()
	}
	return out
}

func rootName() wire.Name {
	return wire.RootName()
}
