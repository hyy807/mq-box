package aha

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// HubDiscovery uses sing-box's protected dialer for control-plane HTTPS.
// Each Discover authenticates independently; switching account configs cannot
// reuse another account's session. Nothing is persisted or written to logs.
type HubDiscovery struct {
	Dialer  N.Dialer
	BaseURL string
}

func (h *HubDiscovery) request(ctx context.Context, p []Parameter) (map[string]any, error) {
	endpoint := h.BaseURL
	if endpoint == "" {
		endpoint = "https://h.ahahub.net/light/dispatch/v2"
	}
	p = append(p, Parameter{"timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10)})
	target := endpoint + "?" + EncodeParameters(p) + "&sign=" + SignControl("/light/dispatch/v2", p)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return h.Dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("aha: invalid hub request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "okhttp/4.9.3")
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aha: hub HTTPS request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("aha: hub HTTP status %d", response.StatusCode)
	}
	var result map[string]any
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4<<20))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		return nil, fmt.Errorf("aha: invalid hub JSON")
	}
	return result, nil
}

func scalar(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return string(v)
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// Field searches named fields only. Persistent credentials must be explicitly
// labelled access_token/persistent_token, or contained inside an access object;
// an arbitrary token field (including signin token) is never accepted.
func field(value any, names ...string) string {
	if m, ok := value.(map[string]any); ok {
		for _, name := range names {
			if v := scalar(m[name]); v != "" {
				return v
			}
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if v := field(m[k], names...); v != "" {
				return v
			}
		}
	}
	if a, ok := value.([]any); ok {
		for _, v := range a {
			if result := field(v, names...); result != "" {
				return result
			}
		}
	}
	return ""
}
func accessToken(value map[string]any) string {
	// cmd=access returns the persistent data-plane credential as token.token.
	// Never accept the signin session token from the signin response.
	if token, ok := value["token"].(map[string]any); ok {
		if result := field(token, "token", "access_token", "persistent_token"); result != "" {
			return result
		}
	}
	if result := field(value, "access_token", "persistent_token"); result != "" {
		return result
	}
	if access, ok := value["access"].(map[string]any); ok {
		if result := field(access, "token", "access_token", "persistent_token"); result != "" {
			return result
		}
	}
	if data, ok := value["data"].(map[string]any); ok {
		return accessToken(data)
	}
	return ""
}

func (h *HubDiscovery) Discover(ctx context.Context, username, password, region string) (Endpoint, error) {
	endpoints, err := h.DiscoverAll(ctx, username, password, region)
	if err != nil {
		return Endpoint{}, err
	}
	if len(endpoints) == 0 {
		return Endpoint{}, fmt.Errorf("aha: no node matching region")
	}
	return endpoints[0], nil
}

// DiscoverAll returns every usable node in the requested region.
func (h *HubDiscovery) DiscoverAll(ctx context.Context, username, password, region string) ([]Endpoint, error) {
	sum := md5.Sum([]byte(username))
	device := hex.EncodeToString(sum[:])
	base := []Parameter{{"app", "ahaspeed"}, {"lang", "zh_hans"}, {"device", device}, {"platform", "windows"}, {"version", "3.13.0"}}
	signin, err := h.request(ctx, append(append([]Parameter{}, base...), Parameter{"cmd", "signin"}, Parameter{"name", username}, Parameter{"password", password}))
	if err != nil {
		return nil, err
	}
	session := field(signin["token"], "token")
	uid := field(signin["user"], "uid")
	if session == "" || uid == "" {
		return nil, fmt.Errorf("aha: signin did not provide session and UID")
	}
	if d := field(signin["token"], "device"); d != "" {
		device = d
		base[2].Value = d
	}
	authenticated := append(append([]Parameter{}, base...), Parameter{"token", session})
	access, err := h.request(ctx, append(append([]Parameter{}, authenticated...), Parameter{"cmd", "access"}))
	if err != nil {
		return nil, err
	}
	token := accessToken(access)
	// Trust only the access response as the source. The service may return the
	// same value for signin and access; equality does not invalidate access.
	if token == "" {
		return nil, fmt.Errorf("aha: access response lacks explicitly labelled persistent token; refusing signin fallback")
	}
	nodes, err := h.request(ctx, append(append([]Parameter{}, authenticated...), Parameter{"cmd", "node"}))
	if err != nil {
		return nil, err
	}
	root, _ := nodes["node"].(map[string]any)
	endpoints := make([]Endpoint, 0)
	seen := make(map[string]struct{})
	for _, tier := range []string{"vip", "regular", "free", "free_signup"} {
		regions, _ := root[tier].(map[string]any)
		keys := make([]string, 0, len(regions))
		for k := range regions {
			if region == "" || strings.EqualFold(k, region) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, r := range keys {
			entries, _ := regions[r].(map[string]any)
			names := make([]string, 0, len(entries))
			for k := range entries {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, name := range names {
				node, _ := entries[name].(map[string]any)
				host := scalar(node["host"])
				if host == "" {
					continue
				}
				backend := field(node, "backend_host", "real_host", "backend_ip", "real_ip")
				if backend == "" {
					backend = BackendHost(host)
				}
				// The reference's camouflage port is not a reliable data-plane port.
				port := uint16(443)
				if text := field(node, "backend_port", "real_port", "port"); text != "" {
					number, err := strconv.ParseUint(text, 10, 16)
					if err != nil || number == 0 {
						continue
					}
					port = uint16(number)
				}
				nodeName := scalar(node["name"])
				if nodeName == "" {
					nodeName = name
				}
				endpoint := Endpoint{Backend: backend, Port: port, Node: nodeName, Handshake: HandshakeOptions{Host: host, UID: uid, AccessToken: token, Device: device, Platform: "windows", Version: "3.13.0", TunnelIP: "10.10.10.2", TunnelGateway: "10.10.10.250"}}
				key := endpoint.Backend + ":" + strconv.FormatUint(uint64(endpoint.Port), 10)
				if _, loaded := seen[key]; loaded {
					continue
				}
				if err := endpoint.Handshake.Validate(); err != nil {
					continue
				}
				seen[key] = struct{}{}
				endpoints = append(endpoints, endpoint)
			}
		}
	}
	return endpoints, nil
}
