// Package register wires every mq-box private protocol into sing-box. It is
// the only entry point upstream code references (include/mods.go).
package register

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	MC "github.com/sagernet/sing-box/mods/modconst"
	"github.com/sagernet/sing-box/mods/protocol/fastup"
	"github.com/sagernet/sing-box/mods/protocol/heysocksxhttp"
	"github.com/sagernet/sing-box/mods/protocol/jumao"
	"github.com/sagernet/sing-box/mods/protocol/lightxtreme"
	"github.com/sagernet/sing-box/mods/protocol/mieru"
	"github.com/sagernet/sing-box/mods/protocol/onesocks"
	"github.com/sagernet/sing-box/mods/protocol/oppa"
	"github.com/sagernet/sing-box/mods/protocol/shadowquic"
	"github.com/sagernet/sing-box/mods/protocol/vlessxhttp"
)

func init() {
	C.ModProxyDisplayName = MC.DisplayName
}

func RegisterOutbounds(registry *outbound.Registry) {
	lightxtreme.RegisterOutbound(registry)
	heysocksxhttp.RegisterOutbound(registry)
	onesocks.RegisterOutbound(registry)
	oppa.RegisterOutbound(registry)
	jumao.RegisterOutbound(registry)
	fastup.RegisterOutbound(registry)
	mieru.RegisterOutbound(registry)
	shadowquic.RegisterOutbound(registry)
	vlessxhttp.RegisterOutbound(registry)
}
