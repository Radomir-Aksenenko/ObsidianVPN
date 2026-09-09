package obsidian

import (
	"bytes"
	"compress/zlib"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ClientConfig holds all connection settings for an Obsidian client.
type ClientConfig struct {
	ProtocolVersion  int      `json:"protocol_version"`
	ServerHost       string   `json:"server_host"`
	ServerPort       string   `json:"server_port"`
	ServerPublicKey  string   `json:"server_public_key"`
	ClientPrivateKey string   `json:"client_private_key,omitempty"`
	NoTLS            bool     `json:"no_tls,omitempty"`
	RealityEnabled   bool     `json:"reality_enabled,omitempty"`
	RealityAuthKey   string   `json:"reality_auth_key,omitempty"`
	RealitySNI       string   `json:"reality_sni,omitempty"`
	Fingerprint      string   `json:"fingerprint,omitempty"`
	SNI              string   `json:"sni,omitempty"`
	SNIPool          []string `json:"sni_pool,omitempty"`
	VerifyTLS        bool     `json:"verify_tls,omitempty"`
	TunInterface     string   `json:"tun_interface,omitempty"`
	TunAddress       string   `json:"tun_address,omitempty"`
	DNS              string   `json:"dns,omitempty"`
	MTU              int      `json:"mtu,omitempty"`
	NoiseMinSec      float64  `json:"noise_min_sec,omitempty"`
	NoiseMaxSec      float64  `json:"noise_max_sec,omitempty"`
	KeepaliveSec     float64  `json:"keepalive_sec,omitempty"`
	Jitter           string   `json:"jitter,omitempty"`
	Profile          string   `json:"profile,omitempty"`
	JunkCount        int      `json:"junk_count,omitempty"`
	JunkMin          int      `json:"junk_min,omitempty"`
	JunkMax          int      `json:"junk_max,omitempty"`
	Signatures       []string `json:"signatures,omitempty"`
	H1Min            uint32   `json:"h1_min,omitempty"`
	H1Max            uint32   `json:"h1_max,omitempty"`
	H4Min            uint32   `json:"h4_min,omitempty"`
	H4Max            uint32   `json:"h4_max,omitempty"`
	RouteIPs         []string `json:"route_ips,omitempty"`
	SplitTunnelMode  string   `json:"split_tunnel_mode,omitempty"`
	SplitSites       []string `json:"split_sites,omitempty"`
	SplitApps        []string `json:"split_apps,omitempty"`
	SplitProcesses   []string `json:"split_processes,omitempty"`
	UDPPort          string   `json:"udp_port,omitempty"`
	EnableUDPData    bool     `json:"enable_udp_data,omitempty"`
	PortPool         []int    `json:"port_pool,omitempty"`
	PortHopIntervalSec int    `json:"port_hop_interval_sec,omitempty"`
	MaxTrailer       int      `json:"max_trailer,omitempty"`
	UseBucketPadding bool     `json:"use_bucket_padding,omitempty"`
	BucketMTU        int      `json:"bucket_mtu,omitempty"`
	EnableIPv6       bool     `json:"enable_ipv6,omitempty"`

	// Management metadata
	KeyserverURL string `json:"_keyserver,omitempty"`
	Token        string `json:"_token,omitempty"`
	Expires      string `json:"_expires,omitempty"`
	MaxDevices   uint32 `json:"_max_devices,omitempty"`
	Label        string `json:"_label,omitempty"`
}

// DefaultClientConfig returns standard production defaults for client connections.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		ProtocolVersion: ProtocolVersion,
		TunAddress:      "10.8.0.2/24",
		DNS:             "1.1.1.1",
		MTU:             1420,
		Profile:         "fast-secure",
		Jitter:          "off",
		JunkCount:       7,
		JunkMin:         50,
		JunkMax:         1000,
		NoiseMinSec:     10,
		NoiseMaxSec:     40,
		KeepaliveSec:    20,
		EnableUDPData:   true,
		Signatures: []string{
			"<b 0xc00000000108><rc 8><b 0x08><rc 8><b 0x0044b000000001><r 1170>",
			"<r 2><b 0x010000010000000000010377777706676f6f676c6503636f6d00000100010000291000000000000000>",
		},
	}
}

// ParseURI parses an obsidian:// or vpn:// URI string into a ClientConfig.
func ParseURI(rawURI string) (*ClientConfig, error) {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return nil, errors.New("empty URI")
	}

	normURI := rawURI
	// Support vpn://obsidian/... format
	if strings.HasPrefix(strings.ToLower(normURI), "vpn://obsidian/") {
		normURI = "obsidian://" + normURI[len("vpn://obsidian/"):]
	} else if strings.HasPrefix(strings.ToLower(normURI), "vpn://") {
		normURI = "obsidian://" + normURI[len("vpn://"):]
	}

	u, err := url.Parse(normURI)
	if err != nil {
		return nil, fmt.Errorf("invalid URI format: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "obsidian" && scheme != "vpn" {
		return nil, fmt.Errorf("unsupported URI scheme: %q", u.Scheme)
	}

	cfg := DefaultClientConfig()

	// Extract server host and port
	host := u.Hostname()
	port := u.Port()
	if host == "" {
		return nil, errors.New("URI is missing host")
	}
	cfg.ServerHost = host
	if port != "" {
		cfg.ServerPort = port
	} else {
		cfg.ServerPort = "8443"
	}

	// Extract server public key from userinfo
	if u.User != nil {
		user := u.User.Username()
		if user != "" {
			cfg.ServerPublicKey = strings.ToLower(user)
		}
	}

	// Fragment is used as server label/remark
	if u.Fragment != "" {
		frag, err := url.QueryUnescape(u.Fragment)
		if err == nil {
			cfg.Label = frag
		} else {
			cfg.Label = u.Fragment
		}
	}

	// Parse query parameters
	q := u.Query()

	if pk := q.Get("pk"); pk != "" {
		cfg.ServerPublicKey = strings.ToLower(pk)
	} else if pbk := q.Get("pbk"); pbk != "" {
		cfg.ServerPublicKey = strings.ToLower(pbk)
	} else if pub := q.Get("server_public_key"); pub != "" {
		cfg.ServerPublicKey = strings.ToLower(pub)
	}

	if cfg.ServerPublicKey == "" {
		return nil, errors.New("missing server_public_key in URI (expected userinfo or pk query parameter)")
	}

	if udpPort := q.Get("udp_port"); udpPort != "" {
		cfg.UDPPort = udpPort
	} else if udp := q.Get("udp"); udp != "" {
		cfg.UDPPort = udp
	} else {
		cfg.UDPPort = cfg.ServerPort
	}

	if val := q.Get("udp_data"); val != "" {
		cfg.EnableUDPData = parseBool(val, true)
	} else if val := q.Get("eu"); val != "" {
		cfg.EnableUDPData = parseBool(val, true)
	}

	if val := q.Get("ipv6"); val != "" {
		cfg.EnableIPv6 = parseBool(val, false)
	} else if val := q.Get("v6"); val != "" {
		cfg.EnableIPv6 = parseBool(val, false)
	}

	if val := q.Get("no_tls"); val != "" {
		cfg.NoTLS = parseBool(val, false)
	} else if val := q.Get("nt"); val != "" {
		cfg.NoTLS = parseBool(val, false)
	}

	sec := strings.ToLower(q.Get("security"))
	if sec == "reality" || parseBool(q.Get("reality"), false) || parseBool(q.Get("re"), false) || q.Get("sni") != "" || q.Get("auth_key") != "" {
		cfg.RealityEnabled = true
		sni := q.Get("sni")
		if sni == "" {
			sni = q.Get("rs")
		}
		if sni == "" {
			sni = q.Get("reality_sni")
		}
		if sni == "" {
			sni = "www.microsoft.com"
		}
		cfg.RealitySNI = sni
		cfg.SNI = sni

		authKey := q.Get("auth_key")
		if authKey == "" {
			authKey = q.Get("rk")
		}
		if authKey == "" {
			authKey = q.Get("sid")
		}
		if authKey == "" {
			authKey = q.Get("reality_auth_key")
		}
		cfg.RealityAuthKey = authKey

		fp := q.Get("fp")
		if fp == "" {
			fp = q.Get("fingerprint")
		}
		if fp == "" {
			fp = "chrome"
		}
		cfg.Fingerprint = fp
	}

	if prof := q.Get("profile"); prof != "" {
		cfg.Profile = prof
	}

	if jit := q.Get("jitter"); jit != "" {
		cfg.Jitter = jit
	}

	if mtuStr := q.Get("mtu"); mtuStr != "" {
		if v, err := strconv.Atoi(mtuStr); err == nil && v > 0 {
			if v > 1420 {
				v = 1420
			}
			cfg.MTU = v
		}
	}

	if dns := q.Get("dns"); dns != "" {
		cfg.DNS = dns
	} else if d := q.Get("d"); d != "" {
		cfg.DNS = d
	}

	if tun := q.Get("tun"); tun != "" {
		cfg.TunAddress = tun
	} else if tunAddr := q.Get("tun_address"); tunAddr != "" {
		cfg.TunAddress = tunAddr
	}

	if j := q.Get("junk"); j != "" {
		if v, err := strconv.Atoi(j); err == nil {
			cfg.JunkCount = v
		}
	}
	if jmin := q.Get("junk_min"); jmin != "" {
		if v, err := strconv.Atoi(jmin); err == nil {
			cfg.JunkMin = v
		}
	}
	if jmax := q.Get("junk_max"); jmax != "" {
		if v, err := strconv.Atoi(jmax); err == nil {
			cfg.JunkMax = v
		}
	}

	if nmin := q.Get("noise_min"); nmin != "" {
		if v, err := strconv.ParseFloat(nmin, 64); err == nil {
			cfg.NoiseMinSec = v
		}
	}
	if nmax := q.Get("noise_max"); nmax != "" {
		if v, err := strconv.ParseFloat(nmax, 64); err == nil {
			cfg.NoiseMaxSec = v
		}
	}
	if ka := q.Get("keepalive"); ka != "" {
		if v, err := strconv.ParseFloat(ka, 64); err == nil {
			cfg.KeepaliveSec = v
		}
	}

	if sigs := q["sig"]; len(sigs) > 0 {
		cfg.Signatures = sigs
	}

	// Key Server / Subscription metadata
	if ks := q.Get("keyserver"); ks != "" {
		cfg.KeyserverURL = ks
	} else if ks := q.Get("ks"); ks != "" {
		cfg.KeyserverURL = ks
	}

	if tok := q.Get("token"); tok != "" {
		cfg.Token = tok
	} else if tok := q.Get("t"); tok != "" {
		cfg.Token = tok
	}

	if exp := q.Get("expires"); exp != "" {
		cfg.Expires = exp
	} else if exp := q.Get("e"); exp != "" {
		cfg.Expires = exp
	}

	if maxDev := q.Get("max_devices"); maxDev != "" {
		if v, err := strconv.ParseUint(maxDev, 10, 32); err == nil {
			cfg.MaxDevices = uint32(v)
		}
	} else if maxDev := q.Get("m"); maxDev != "" {
		if v, err := strconv.ParseUint(maxDev, 10, 32); err == nil {
			cfg.MaxDevices = uint32(v)
		}
	}

	if clientKey := q.Get("client_key"); clientKey != "" {
		cfg.ClientPrivateKey = strings.ToLower(clientKey)
	}

	return &cfg, nil
}

// EncodeURI serializes a ClientConfig into a canonical obsidian:// URI.
func EncodeURI(cfg *ClientConfig, label string) string {
	if cfg == nil {
		return ""
	}

	host := cfg.ServerHost
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	port := cfg.ServerPort
	if port == "" {
		port = "8443"
	}

	u := url.URL{
		Scheme: "obsidian",
		User:   url.User(cfg.ServerPublicKey),
		Host:   net.JoinHostPort(host, port),
	}

	q := url.Values{}

	udpPort := cfg.UDPPort
	if udpPort == "" {
		udpPort = port
	}
	if udpPort != port {
		q.Set("udp_port", udpPort)
	}

	if !cfg.EnableUDPData {
		q.Set("udp_data", "0")
	}

	if cfg.EnableIPv6 {
		q.Set("ipv6", "1")
	}

	if cfg.NoTLS {
		q.Set("no_tls", "1")
	}

	if cfg.RealityEnabled {
		q.Set("security", "reality")
		if cfg.RealitySNI != "" {
			q.Set("sni", cfg.RealitySNI)
		}
		if cfg.RealityAuthKey != "" {
			q.Set("auth_key", cfg.RealityAuthKey)
		}
		if cfg.Fingerprint != "" && cfg.Fingerprint != "chrome" {
			q.Set("fp", cfg.Fingerprint)
		}
	}

	if cfg.Profile != "" && cfg.Profile != "fast-secure" {
		q.Set("profile", cfg.Profile)
	}

	if cfg.MTU != 0 && cfg.MTU != 1420 {
		q.Set("mtu", strconv.Itoa(cfg.MTU))
	}

	if cfg.DNS != "" && cfg.DNS != "1.1.1.1" && cfg.DNS != "10.8.0.1" {
		q.Set("dns", cfg.DNS)
	}

	if cfg.KeyserverURL != "" {
		q.Set("keyserver", cfg.KeyserverURL)
	}
	if cfg.Token != "" {
		q.Set("token", cfg.Token)
	}
	if cfg.Expires != "" {
		q.Set("expires", cfg.Expires)
	}
	if cfg.MaxDevices > 0 {
		q.Set("max_devices", strconv.FormatUint(uint64(cfg.MaxDevices), 10))
	}
	if cfg.ClientPrivateKey != "" {
		q.Set("client_key", cfg.ClientPrivateKey)
	}

	u.RawQuery = q.Encode()

	displayLabel := label
	if displayLabel == "" {
		displayLabel = cfg.Label
	}
	if displayLabel != "" {
		u.Fragment = displayLabel
	}

	return u.String()
}

// DecodeKey decodes either an obsidian:// / vpn:// URI, or a legacy OBSDN-XXXX-... key.
func DecodeKey(keyStr string) (*ClientConfig, error) {
	s := strings.TrimSpace(keyStr)
	if s == "" {
		return nil, errors.New("empty key or URI")
	}

	// Check if this is a URI
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "obsidian://") || strings.HasPrefix(lower, "vpn://") {
		return ParseURI(s)
	}

	// Otherwise, decode legacy OBSDN-... Base32+Zlib key
	clean := strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	clean = strings.TrimPrefix(clean, "OBSDN-")
	clean = strings.ReplaceAll(clean, "-", "")

	// Pad with '=' for standard base32
	if pad := (8 - len(clean)%8) % 8; pad > 0 {
		clean += strings.Repeat("=", pad)
	}

	compressed, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 in OBSDN key: %w", err)
	}

	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("invalid zlib payload in OBSDN key: %w", err)
	}
	defer zr.Close()

	var jsonBytes bytes.Buffer
	if _, err := io.Copy(&jsonBytes, zr); err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}

	var compact map[string]interface{}
	if err := json.Unmarshal(jsonBytes.Bytes(), &compact); err != nil {
		return nil, fmt.Errorf("failed to parse JSON inside key: %w", err)
	}

	// Validate required fields: h, p, u, k
	for _, req := range []string{"h", "p", "u", "k"} {
		if _, ok := compact[req]; !ok {
			return nil, fmt.Errorf("OBSDN key is missing required field: %s", req)
		}
	}

	cfg := DefaultClientConfig()
	cfg.ServerHost = fmt.Sprintf("%v", compact["h"])
	cfg.ServerPort = fmt.Sprintf("%v", compact["p"])
	cfg.ServerPublicKey = fmt.Sprintf("%v", compact["k"])

	if u, ok := compact["u"]; ok {
		cfg.UDPPort = fmt.Sprintf("%v", u)
	}
	if eu, ok := compact["eu"].(bool); ok {
		cfg.EnableUDPData = eu
	}
	if v6, ok := compact["v6"].(bool); ok {
		cfg.EnableIPv6 = v6
	}
	if nt, ok := compact["nt"].(bool); ok {
		cfg.NoTLS = nt
	}
	if d, ok := compact["d"].(string); ok && d != "" {
		cfg.DNS = d
	}
	if mtu, ok := compact["mtu"].(float64); ok && mtu > 0 {
		cfg.MTU = int(mtu)
	}
	if j, ok := compact["j"].(float64); ok {
		cfg.JunkCount = int(j)
	}
	if ns, ok := compact["ns"].(float64); ok {
		cfg.NoiseMinSec = ns
	}
	if nx, ok := compact["nx"].(float64); ok {
		cfg.NoiseMaxSec = nx
	}
	if ka, ok := compact["ka"].(float64); ok {
		cfg.KeepaliveSec = ka
	}

	re, _ := compact["re"].(bool)
	rk, _ := compact["rk"].(string)
	rs, _ := compact["rs"].(string)
	if re || rk != "" || rs != "" {
		cfg.RealityEnabled = true
		cfg.RealityAuthKey = rk
		if rs == "" {
			rs = "www.microsoft.com"
		}
		cfg.RealitySNI = rs
		cfg.SNI = rs
		cfg.Fingerprint = "chrome"
	}

	if ks, ok := compact["ks"].(string); ok {
		cfg.KeyserverURL = ks
	}
	if t, ok := compact["t"].(string); ok {
		cfg.Token = t
	}
	if e, ok := compact["e"].(string); ok {
		cfg.Expires = e
	}
	if m, ok := compact["m"].(float64); ok {
		cfg.MaxDevices = uint32(m)
	}
	if c, ok := compact["c"].(string); ok {
		c = strings.ToLower(strings.TrimSpace(c))
		if b, err := hex.DecodeString(c); err == nil && len(b) == 32 {
			cfg.ClientPrivateKey = c
		}
	}

	return &cfg, nil
}

func parseBool(s string, defaultVal bool) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultVal
	}
}
