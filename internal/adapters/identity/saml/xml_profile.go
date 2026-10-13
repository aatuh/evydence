package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
const subjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
const exclusiveCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#"
const envelopedTransform = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
const sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256"

var xmlID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
var errProfile = errors.New("unsupported SAML XML signature profile")

func literalAttribute(el *etree.Element, key string) string {
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == key {
			return a.Value
		}
	}
	return ""
}

// etree's unqualified selectors treat namespace prefixes as wildcards. Keep
// the literal assertion ID first for the library's own root-ID lookup. XML
// Signature's library canonicalizer determines the signed attribute order.
func literalRootIDFirst(el *etree.Element) {
	for i, a := range el.Attr {
		if a.Space == "" && a.Key == "ID" {
			copy(el.Attr[1:i+1], el.Attr[:i])
			el.Attr[0] = a
			return
		}
	}
}

// Bound work before etree or the signature library sees untrusted XML. No DTD,
// external entity, comments, duplicate expanded attributes or ambiguous IDs.
func boundedXML(ctx context.Context, raw string) (*etree.Element, error) {
	if len(raw) == 0 || len(raw) > 65536 || !utf8.ValidString(raw) {
		return nil, errProfile
	}
	d := xml.NewDecoder(strings.NewReader(raw))
	d.Strict = true
	depth, nodes, roots := 0, 0, 0
	declaration := false
	ids := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errProfile
		}
		nodes++
		if nodes > 1024 {
			return nil, errProfile
		}
		switch t := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 32 || roots != 1 || len(t.Attr) > 32 {
				return nil, errProfile
			}
			attrs := map[xml.Name]bool{}
			for _, a := range t.Attr {
				if attrs[a.Name] {
					return nil, errProfile
				}
				attrs[a.Name] = true
				if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
					continue
				}
				if strings.EqualFold(a.Name.Local, "id") {
					if a.Name.Space != "" || a.Name.Local != "ID" || !xmlID.MatchString(a.Value) || ids[a.Value] {
						return nil, errProfile
					}
					ids[a.Value] = true
				}
			}
		case xml.EndElement:
			depth--
		case xml.Directive, xml.Comment:
			return nil, errProfile
		case xml.ProcInst:
			if t.Target != "xml" || roots != 0 || declaration {
				return nil, errProfile
			}
			declaration = true
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return nil, errProfile
			}
		}
	}
	if roots != 1 || depth != 0 {
		return nil, errProfile
	}
	doc := etree.NewDocument()
	doc.ReadSettings.MaxDepth = 32
	if doc.ReadFromString(raw) != nil || doc.Root() == nil {
		return nil, errProfile
	}
	return doc.Root(), nil
}

func allowedAttrs(el *etree.Element, names ...string) bool {
	for _, a := range el.Attr {
		if a.Space == "xmlns" || a.Space == "" && a.Key == "xmlns" {
			continue
		}
		allowed := false
		for _, name := range names {
			allowed = allowed || a.Space == "" && a.Key == name
		}
		if !allowed {
			return false
		}
	}
	return true
}

func named(el *etree.Element, ns, name string) bool {
	return el != nil && el.NamespaceURI() == ns && el.Tag == name
}

func children(el *etree.Element, ns string, permitted ...string) (map[string][]*etree.Element, error) {
	out := map[string][]*etree.Element{}
	for _, token := range el.Child {
		switch t := token.(type) {
		case *etree.CharData:
			if strings.TrimSpace(t.Data) != "" {
				return nil, errProfile
			}
		case *etree.Element:
			allowed := false
			for _, name := range permitted {
				allowed = allowed || named(t, ns, name)
			}
			if !allowed {
				return nil, errProfile
			}
			out[t.Tag] = append(out[t.Tag], t)
		default:
			return nil, errProfile
		}
	}
	return out, nil
}

func exactChildren(el *etree.Element, ns string, names ...string) ([]*etree.Element, error) {
	if _, err := children(el, ns, names...); err != nil {
		return nil, err
	}
	got := el.ChildElements()
	if len(got) != len(names) {
		return nil, errProfile
	}
	for i, name := range names {
		if !named(got[i], ns, name) {
			return nil, errProfile
		}
	}
	return got, nil
}

func leaf(el *etree.Element, max int) (string, error) {
	var text strings.Builder
	for _, token := range el.Child {
		t, ok := token.(*etree.CharData)
		if !ok {
			return "", errProfile
		}
		text.WriteString(t.Data)
	}
	value := text.String()
	if value == "" || len(value) > max {
		return "", errProfile
	}
	return value, nil
}

func base64Value(el *etree.Element, size int) ([]byte, error) {
	value, err := leaf(el, 16384)
	if err != nil {
		return nil, err
	}
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, value)
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value || size > 0 && len(raw) != size {
		return nil, errProfile
	}
	return raw, nil
}

// The supported signature has one same-document reference to the assertion,
// SHA-256, an enveloped transform and exclusive C14N without comments/parameters.
func signatureProfile(assertion *etree.Element) error {
	cs := assertion.ChildElements()
	if len(cs) < 2 || !named(cs[0], assertionNamespace, "Issuer") || !named(cs[1], dsig.Namespace, "Signature") {
		return errProfile
	}
	sig := cs[1]
	if !allowedAttrs(sig) {
		return errProfile
	}
	parts, err := exactChildren(sig, dsig.Namespace, "SignedInfo", "SignatureValue", "KeyInfo")
	if err != nil {
		return err
	}
	for _, part := range parts {
		if !allowedAttrs(part) {
			return errProfile
		}
	}
	info, err := exactChildren(parts[0], dsig.Namespace, "CanonicalizationMethod", "SignatureMethod", "Reference")
	if err != nil {
		return err
	}
	if !algorithmLeaf(info[0], exclusiveCanonicalization) || !algorithmLeaf(info[1], dsig.RSASHA256SignatureMethod) || !allowedAttrs(info[2], "URI") || literalAttribute(info[2], "URI") != "#"+literalAttribute(assertion, "ID") {
		return errProfile
	}
	ref, err := exactChildren(info[2], dsig.Namespace, "Transforms", "DigestMethod", "DigestValue")
	if err != nil || !allowedAttrs(ref[0]) || !algorithmLeaf(ref[1], sha256Digest) || !allowedAttrs(ref[2]) {
		return errProfile
	}
	transforms, err := exactChildren(ref[0], dsig.Namespace, "Transform", "Transform")
	if err != nil || !algorithmLeaf(transforms[0], envelopedTransform) || !algorithmLeaf(transforms[1], exclusiveCanonicalization) {
		return errProfile
	}
	if _, err := base64Value(ref[2], 32); err != nil {
		return err
	}
	if raw, err := base64Value(parts[1], 0); err != nil || len(raw) < 256 || len(raw) > 1024 {
		return errProfile
	}
	keyInfo, err := exactChildren(parts[2], dsig.Namespace, "X509Data")
	if err != nil || !allowedAttrs(keyInfo[0]) {
		return errProfile
	}
	cert, err := exactChildren(keyInfo[0], dsig.Namespace, "X509Certificate")
	if err != nil || !allowedAttrs(cert[0]) {
		return errProfile
	}
	if _, err := base64Value(cert[0], 0); err != nil {
		return err
	}
	return nil
}

func algorithmLeaf(el *etree.Element, algorithm string) bool {
	return allowedAttrs(el, "Algorithm") && literalAttribute(el, "Algorithm") == algorithm && len(el.ChildElements()) == 0 && strings.TrimSpace(el.Text()) == ""
}
