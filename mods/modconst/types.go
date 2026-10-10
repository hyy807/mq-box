// Package modconst holds the outbound type names of every mq-box private
// protocol. None of them overlaps an upstream sing-box type, so upstream
// protocols are never shadowed or modified.
package modconst

const (
	TypeLightXtreme   = "lightxtreme"
	TypeHeysocksXhttp = "heysocks-xhttp"
	TypeOneSocks      = "onesocks"
	TypeOppa          = "oppa"
	TypeJumao         = "jumao"
	TypeFastUP        = "fastup"
	TypeMieru         = "mieru"
	TypeShadowQUIC    = "shadowquic"
	TypeVLESSXHTTP    = "vless-xhttp"
	TypeVLESSX365     = "vless-x365"
)

// DisplayName returns the UI name of a private protocol, or "" when the type
// is not a private one.
func DisplayName(outboundType string) string {
	switch outboundType {
	case TypeLightXtreme:
		return "LightXtreme"
	case TypeHeysocksXhttp:
		return "Heysocks Xhttp"
	case TypeOneSocks:
		return "OneSocks"
	case TypeOppa:
		return "Oppa"
	case TypeJumao:
		return "JuMao"
	case TypeFastUP:
		return "FastUP"
	case TypeMieru:
		return "Mieru"
	case TypeShadowQUIC:
		return "ShadowQUIC"
	case TypeVLESSXHTTP:
		return "VLESS XHTTP"
	case TypeVLESSX365:
		return "VLESS X365"
	}
	return ""
}
