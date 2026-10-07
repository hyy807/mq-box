# mq-box private protocols

Everything private lives in this directory. Upstream sing-box code is kept
byte-identical except for these hooks:

| File | Change |
|---|---|
| `include/mods.go` | new file, imports `mods/register` |
| `include/registry.go` | one line `registerModOutbounds(registry) // mq-box` |
| `constant/proxy_mods.go` | new file, display-name hook |
| `constant/proxy.go` | 5 lines in `ProxyDisplayName` default branch, marked `// mq-box` |
| `go.mod` / `go.sum` | extra dependencies (mieru, jls, restls) |

## Outbound types

| type | UI name | Notes |
|---|---|---|
| `lightxtreme` | LightXtreme | AnyTLS + LightXtreme auth (`platform_marker` optional) |
| `heysocks-xhttp` | Heysocks Xhttp | Heysocks xstream over TCP |
| `onesocks` | OneSocks | AES-CTR stream over TCP |
| `oppa` | Oppa | Oppa / sslhop |
| `jumao` | JuMao | watermarked-IV shadowsocks |
| `fastup` | FastUP | Trojan, key = hex(md5(password + mpw)) |
| `mieru` | Mieru | mieru v3 |
| `shadowquic` | ShadowQUIC | ShadowQUIC (JLS) |
| `vless-xhttp` | VLESS XHTTP | VLESS over XHTTP, fields under `xhttp` |

Private protocols use `mods/modtls`, whose `tls` block accepts the upstream
fields plus `jls` / `restls`, the fixed REALITY client and extra uTLS
fingerprints (`chrome_106`, `chrome_120`, ...). See `ci/all-protocols.json`.

## Upstream sync

`.github/workflows/sync-upstream.yml` merges `SagerNet/sing-box@testing` daily.
