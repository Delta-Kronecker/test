package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

type GeoFraudConfig struct {
	XrayPath       string
	MaxWorkers     int
	Timeout        time.Duration
	InputFile      string
	OutputDir      string
	StartPort      int
	EndPort        int
	RequestTimeout time.Duration
}

type ProxyInfo struct {
	URL          string
	IP           string
	Country      string
	CountryCode  string
	FraudScore   int
	Error        string
	ResponseTime float64
}

type PortManager struct {
	startPort      int
	endPort        int
	availablePorts chan int
	usedPorts      sync.Map
	mu             sync.Mutex
}

func NewPortManager(startPort, endPort int) *PortManager {
	pm := &PortManager{
		startPort:      startPort,
		endPort:        endPort,
		availablePorts: make(chan int, endPort-startPort+1),
	}
	pm.initializePortPool()
	return pm
}

func (pm *PortManager) initializePortPool() {
	log.Printf("Initializing port pool (%d-%d)...", pm.startPort, pm.endPort)
	availableCount := 0

	for port := pm.startPort; port <= pm.endPort; port++ {
		select {
		case pm.availablePorts <- port:
			availableCount++
		default:
		}
	}

	log.Printf("Port pool initialized with %d available ports", availableCount)
}

func (pm *PortManager) GetAvailablePort() (int, bool) {
	select {
	case port := <-pm.availablePorts:
		pm.usedPorts.Store(port, time.Now())
		return port, true
	case <-time.After(100 * time.Millisecond):
		return 0, false
	}
}

func (pm *PortManager) ReleasePort(port int) {
	pm.usedPorts.Delete(port)
	go func() {
		time.Sleep(50 * time.Millisecond)
		select {
		case pm.availablePorts <- port:
		default:
		}
	}()
}

type ProcessManager struct {
	processes sync.Map
	mu        sync.Mutex
}

func NewProcessManager() *ProcessManager {
	return &ProcessManager{}
}

func (pm *ProcessManager) RegisterProcess(pid int, cmd *exec.Cmd) {
	pm.processes.Store(pid, cmd)
}

func (pm *ProcessManager) UnregisterProcess(pid int) {
	pm.processes.Delete(pid)
}

func (pm *ProcessManager) KillProcess(pid int) error {
	if value, ok := pm.processes.Load(pid); ok {
		if cmd, ok := value.(*exec.Cmd); ok {
			if cmd.Process != nil {
				cmd.Process.Kill()
				pm.UnregisterProcess(pid)
				return nil
			}
		}
	}
	return fmt.Errorf("process not found")
}

func (pm *ProcessManager) Cleanup() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var pids []int
	pm.processes.Range(func(key, value interface{}) bool {
		if pid, ok := key.(int); ok {
			pids = append(pids, pid)
		}
		return true
	})

	for _, pid := range pids {
		pm.KillProcess(pid)
	}

	time.Sleep(100 * time.Millisecond)
}

type GeoFraudChecker struct {
	config         *GeoFraudConfig
	portManager    *PortManager
	processManager *ProcessManager
	stats          struct {
		total     int64
		success   int64
		failed    int64
		processed int64
	}
	countryFlags map[string]string
}

func NewGeoFraudChecker(config *GeoFraudConfig) *GeoFraudChecker {
	gfc := &GeoFraudChecker{
		config:         config,
		portManager:    NewPortManager(config.StartPort, config.EndPort),
		processManager: NewProcessManager(),
		countryFlags:   initCountryFlags(),
	}
	return gfc
}

func initCountryFlags() map[string]string {
	return map[string]string{
		// Europe
		"US": "🇺🇸", "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "CA": "🇨🇦",
		"NL": "🇳🇱", "SE": "🇸🇪", "CH": "🇨🇭", "SG": "🇸🇬", "JP": "🇯🇵",
		"AU": "🇦🇺", "ES": "🇪🇸", "IT": "🇮🇹", "BR": "🇧🇷", "IN": "🇮🇳",
		"CN": "🇨🇳", "KR": "🇰🇷", "RU": "🇷🇺", "TR": "🇹🇷", "PL": "🇵🇱",
		"UA": "🇺🇦", "RO": "🇷🇴", "CZ": "🇨🇿", "AT": "🇦🇹", "BE": "🇧🇪",
		"DK": "🇩🇰", "FI": "🇫🇮", "NO": "🇳🇴", "IE": "🇮🇪", "PT": "🇵🇹",
		"GR": "🇬🇷", "HU": "🇭🇺", "BG": "🇧🇬", "HR": "🇭🇷", "LT": "🇱🇹",
		"LV": "🇱🇻", "EE": "🇪🇪", "SK": "🇸🇰", "SI": "🇸🇮", "LU": "🇱🇺",
		"MT": "🇲🇹", "CY": "🇨🇾", "IS": "🇮🇸", "LI": "🇱🇮", "MC": "🇲🇨",

		// Middle East & Asia
		"IL": "🇮🇱", "AE": "🇦🇪", "SA": "🇸🇦", "QA": "🇶🇦", "KW": "🇰🇼",
		"IR": "🇮🇷", "IQ": "🇮🇶", "AF": "🇦🇫", "PK": "🇵🇰", "BD": "🇧🇩",
		"HK": "🇭🇰", "TW": "🇹🇼", "MY": "🇲🇾", "TH": "🇹🇭", "ID": "🇮🇩",
		"PH": "🇵🇭", "VN": "🇻🇳", "MN": "🇲🇳", "KZ": "🇰🇿", "UZ": "🇺🇿",
		"AZ": "🇦🇿", "GE": "🇬🇪", "AM": "🇦🇲", "LB": "🇱🇧", "JO": "🇯🇴",
		"SY": "🇸🇾", "YE": "🇾🇪", "OM": "🇴🇲", "BH": "🇧🇭",

		// Americas
		"MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "PE": "🇵🇪",
		"VE": "🇻🇪", "UY": "🇺🇾", "EC": "🇪🇨", "BO": "🇧🇴", "PY": "🇵🇾",
		"CR": "🇨🇷", "PA": "🇵🇦", "GT": "🇬🇹", "SV": "🇸🇻", "HN": "🇭🇳",
		"NI": "🇳🇮", "CU": "🇨🇺", "DO": "🇩🇴", "JM": "🇯🇲", "TT": "🇹🇹",

		// Africa & Oceania
		"ZA": "🇿🇦", "EG": "🇪🇬", "NZ": "🇳🇿", "NG": "🇳🇬", "KE": "🇰🇪",
		"MA": "🇲🇦", "DZ": "🇩🇿", "TN": "🇹🇳", "LY": "🇱🇾", "ET": "🇪🇹",
		"GH": "🇬🇭", "UG": "🇺🇬", "TZ": "🇹🇿", "ZW": "🇿🇼", "ZM": "🇿🇲",

		// Others
		"XX": "🏴", "UNKNOWN": "🏴",
	}
}

func (gfc *GeoFraudChecker) getCountryFlag(countryCode string) string {
	if flag, ok := gfc.countryFlags[strings.ToUpper(countryCode)]; ok {
		return flag
	}
	return "🏴"
}

func (gfc *GeoFraudChecker) LoadURLsFromFile() ([]string, error) {
	file, err := os.Open(gfc.config.InputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract URL (handle lines with metadata)
		if strings.Contains(line, "://") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	log.Printf("Loaded %d URLs from file", len(urls))
	return urls, nil
}

func (gfc *GeoFraudChecker) createXrayConfig(proxyURL string, listenPort int) (string, error) {
	// Parse proxy URL and create appropriate Xray config
	var config map[string]interface{}
	var err error

	if strings.HasPrefix(proxyURL, "ss://") {
		config, err = gfc.createShadowsocksConfig(proxyURL, listenPort)
	} else if strings.HasPrefix(proxyURL, "vmess://") {
		config, err = gfc.createVMessConfig(proxyURL, listenPort)
	} else if strings.HasPrefix(proxyURL, "vless://") {
		config, err = gfc.createVLESSConfig(proxyURL, listenPort)
	} else {
		return "", fmt.Errorf("unsupported protocol")
	}

	if err != nil {
		return "", err
	}

	tmpFile, err := os.CreateTemp("", "xray-geo-*.json")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

func (gfc *GeoFraudChecker) createShadowsocksConfig(proxyURL string, listenPort int) (map[string]interface{}, error) {
	// Parse Shadowsocks URL: ss://base64(method:password)@server:port#remark
	proxyURL = strings.TrimPrefix(proxyURL, "ss://")

	// Split remark if exists
	parts := strings.Split(proxyURL, "#")
	proxyURL = parts[0]

	// Split auth and server
	authServer := strings.Split(proxyURL, "@")
	if len(authServer) != 2 {
		return nil, fmt.Errorf("invalid shadowsocks URL format")
	}

	// Decode base64 auth
	authDecoded, err := base64.StdEncoding.DecodeString(authServer[0])
	if err != nil {
		authDecoded, err = base64.RawStdEncoding.DecodeString(authServer[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode auth: %v", err)
		}
	}

	// Parse method:password
	authParts := strings.SplitN(string(authDecoded), ":", 2)
	if len(authParts) != 2 {
		return nil, fmt.Errorf("invalid auth format")
	}
	method := authParts[0]
	password := authParts[1]

	// Parse server:port
	serverPort := strings.Split(authServer[1], ":")
	if len(serverPort) != 2 {
		return nil, fmt.Errorf("invalid server:port format")
	}
	server := serverPort[0]
	port, err := strconv.Atoi(serverPort[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "error",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  false,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": "shadowsocks",
				"settings": map[string]interface{}{
					"servers": []map[string]interface{}{
						{
							"address":  server,
							"port":     port,
							"method":   method,
							"password": password,
						},
					},
				},
			},
		},
	}, nil
}

func (gfc *GeoFraudChecker) createVMessConfig(proxyURL string, listenPort int) (map[string]interface{}, error) {
	// Parse VMess URL: vmess://base64(json)
	proxyURL = strings.TrimPrefix(proxyURL, "vmess://")

	// Decode base64
	jsonData, err := base64.StdEncoding.DecodeString(proxyURL)
	if err != nil {
		jsonData, err = base64.RawStdEncoding.DecodeString(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to decode vmess: %v", err)
		}
	}

	// Parse JSON
	var vmessConfig map[string]interface{}
	if err := json.Unmarshal(jsonData, &vmessConfig); err != nil {
		return nil, fmt.Errorf("failed to parse vmess json: %v", err)
	}

	// Extract fields
	address := getString(vmessConfig, "add")
	portStr := getString(vmessConfig, "port")
	id := getString(vmessConfig, "id")
	aidStr := getString(vmessConfig, "aid")
	network := getString(vmessConfig, "net")
	if network == "" {
		network = "tcp"
	}

	port, _ := strconv.Atoi(portStr)
	alterID, _ := strconv.Atoi(aidStr)

	outbound := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": address,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":       id,
							"alterId":  alterID,
							"security": getString(vmessConfig, "scy"),
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network": network,
		},
	}

	// Add TLS if present
	if getString(vmessConfig, "tls") == "tls" {
		streamSettings := outbound["streamSettings"].(map[string]interface{})
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"allowInsecure": true,
			"serverName":    getString(vmessConfig, "sni"),
		}
	}

	// Add WebSocket settings if needed
	if network == "ws" {
		streamSettings := outbound["streamSettings"].(map[string]interface{})
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": getString(vmessConfig, "path"),
			"headers": map[string]interface{}{
				"Host": getString(vmessConfig, "host"),
			},
		}
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "error",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  false,
				},
			},
		},
		"outbounds": []map[string]interface{}{outbound},
	}, nil
}

func (gfc *GeoFraudChecker) createVLESSConfig(proxyURL string, listenPort int) (map[string]interface{}, error) {
	// Parse VLESS URL: vless://uuid@server:port?params#remark
	proxyURL = strings.TrimPrefix(proxyURL, "vless://")

	// Split remark
	parts := strings.Split(proxyURL, "#")
	proxyURL = parts[0]

	// Split params
	parts = strings.Split(proxyURL, "?")
	mainPart := parts[0]
	params := make(map[string]string)
	if len(parts) > 1 {
		paramsParsed, _ := url.ParseQuery(parts[1])
		for key, values := range paramsParsed {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}
	}

	// Parse uuid@server:port
	atSplit := strings.Split(mainPart, "@")
	if len(atSplit) != 2 {
		return nil, fmt.Errorf("invalid vless URL format")
	}

	uuid := atSplit[0]
	serverPort := strings.Split(atSplit[1], ":")
	if len(serverPort) != 2 {
		return nil, fmt.Errorf("invalid server:port format")
	}

	server := serverPort[0]
	port, err := strconv.Atoi(serverPort[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	network := params["type"]
	if network == "" {
		network = "tcp"
	}

	outbound := map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": server,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":         uuid,
							"encryption": params["encryption"],
							"flow":       params["flow"],
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network": network,
		},
	}

	// Add TLS/Reality settings
	security := params["security"]
	if security == "tls" || security == "reality" {
		streamSettings := outbound["streamSettings"].(map[string]interface{})
		streamSettings["security"] = security

		tlsSettings := map[string]interface{}{
			"allowInsecure": true,
			"serverName":    params["sni"],
		}

		if security == "tls" {
			streamSettings["tlsSettings"] = tlsSettings
		} else {
			streamSettings["realitySettings"] = tlsSettings
		}
	}

	// Add transport settings
	if network == "ws" {
		streamSettings := outbound["streamSettings"].(map[string]interface{})
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": params["path"],
			"headers": map[string]interface{}{
				"Host": params["host"],
			},
		}
	} else if network == "grpc" {
		streamSettings := outbound["streamSettings"].(map[string]interface{})
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": params["serviceName"],
		}
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "error",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  false,
				},
			},
		},
		"outbounds": []map[string]interface{}{outbound},
	}, nil
}

func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func (gfc *GeoFraudChecker) startXrayProcess(configFile string) (*exec.Cmd, error) {
	cmd := exec.Command(gfc.config.XrayPath, "run", "-config", configFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cmd, nil
}

func (gfc *GeoFraudChecker) getIPInfo(proxyPort int) (string, string, string, error) {
	// Wait for proxy to be ready
	time.Sleep(500 * time.Millisecond)

	// Test if proxy is responsive
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if err != nil {
		return "", "", "", fmt.Errorf("proxy not responsive: %v", err)
	}
	conn.Close()

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return "", "", "", fmt.Errorf("socks5 dialer error: %v", err)
	}

	transport := &http.Transport{
		Dial:                dialer.Dial,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   gfc.config.RequestTimeout,
	}

	// Try to get IP from multiple sources
	// First try: ipify (simple and reliable)
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		if json.Unmarshal(body, &result) == nil {
			if ip, ok := result["ip"].(string); ok {
				// Get country from ip-api.com
				country, countryCode := gfc.getCountryFromIPAPI(client, ip)
				return ip, country, countryCode, nil
			}
		}
	}

	// Fallback: httpbin
	resp, err = client.Get("https://httpbin.org/ip")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get IP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", "", fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", err
	}

	var result map[string]interface{}
	if json.Unmarshal(body, &result) == nil {
		if origin, ok := result["origin"].(string); ok {
			ip := strings.Split(origin, ",")[0]
			ip = strings.TrimSpace(ip)

			// Get country from ip-api.com
			country, countryCode := gfc.getCountryFromIPAPI(client, ip)
			return ip, country, countryCode, nil
		}
	}

	return "", "", "", fmt.Errorf("failed to extract IP")
}

func (gfc *GeoFraudChecker) getCountryFromIPAPI(client *http.Client, ip string) (string, string) {
	// Use ip-api.com for geolocation (free, no key required)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=country,countryCode", ip)

	resp, err := client.Get(url)
	if err != nil {
		return "Unknown", "XX"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "Unknown", "XX"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown", "XX"
	}

	var result map[string]interface{}
	if json.Unmarshal(body, &result) == nil {
		country := getString(result, "country")
		countryCode := getString(result, "countryCode")
		if country != "" && countryCode != "" {
			return country, countryCode
		}
	}

	return "Unknown", "XX"
}

func (gfc *GeoFraudChecker) getFraudScore(ip string, proxyPort int) (int, error) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return 0, err
	}

	transport := &http.Transport{
		Dial:                dialer.Dial,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   gfc.config.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allow redirects
		},
	}

	url := fmt.Sprintf("https://scamalytics.com/ip/%s", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	// Add headers to mimic a browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	// Extract fraud score from response
	fraudScore := gfc.extractFraudScore(string(body))
	return fraudScore, nil
}

func (gfc *GeoFraudChecker) extractFraudScore(html string) int {
	// Try multiple patterns to extract fraud score

	// Pattern 1: Fraud Score: XX
	scoreRegex1 := regexp.MustCompile(`Fraud\s+Score:\s*(\d+)`)
	matches := scoreRegex1.FindStringSubmatch(html)
	if len(matches) > 1 {
		var score int
		fmt.Sscanf(matches[1], "%d", &score)
		return score
	}

	// Pattern 2: <div class="score">XX</div>
	scoreRegex2 := regexp.MustCompile(`<div[^>]*class="score"[^>]*>(\d+)</div>`)
	matches = scoreRegex2.FindStringSubmatch(html)
	if len(matches) > 1 {
		var score int
		fmt.Sscanf(matches[1], "%d", &score)
		return score
	}

	// Pattern 3: score">XX<
	scoreRegex3 := regexp.MustCompile(`score">(\d+)<`)
	matches = scoreRegex3.FindStringSubmatch(html)
	if len(matches) > 1 {
		var score int
		fmt.Sscanf(matches[1], "%d", &score)
		return score
	}

	// Pattern 4: "score":XX
	scoreRegex4 := regexp.MustCompile(`"score"\s*:\s*(\d+)`)
	matches = scoreRegex4.FindStringSubmatch(html)
	if len(matches) > 1 {
		var score int
		fmt.Sscanf(matches[1], "%d", &score)
		return score
	}

	// Pattern 5: Look for gauge or panel with score
	scoreRegex5 := regexp.MustCompile(`(?i)fraud.*?score.*?(\d{1,3})`)
	matches = scoreRegex5.FindStringSubmatch(html)
	if len(matches) > 1 {
		var score int
		fmt.Sscanf(matches[1], "%d", &score)
		if score <= 100 {
			return score
		}
	}

	log.Printf("Warning: Could not extract fraud score from scamalytics response")
	return 0
}

func (gfc *GeoFraudChecker) ProcessURL(proxyURL string) *ProxyInfo {
	startTime := time.Now()
	info := &ProxyInfo{
		URL: proxyURL,
	}

	var proxyPort int
	var process *exec.Cmd
	var configFile string

	defer func() {
		if configFile != "" {
			os.Remove(configFile)
		}
		if process != nil && process.Process != nil {
			process.Process.Kill()
			gfc.processManager.UnregisterProcess(process.Process.Pid)
		}
		if proxyPort > 0 {
			gfc.portManager.ReleasePort(proxyPort)
		}
		info.ResponseTime = time.Since(startTime).Seconds()
	}()

	// Get available port
	var ok bool
	proxyPort, ok = gfc.portManager.GetAvailablePort()
	if !ok || proxyPort == 0 {
		info.Error = "no available port"
		return info
	}

	// Create Xray config
	var err error
	configFile, err = gfc.createXrayConfig(proxyURL, proxyPort)
	if err != nil {
		info.Error = fmt.Sprintf("config error: %v", err)
		return info
	}

	// Start Xray process
	process, err = gfc.startXrayProcess(configFile)
	if err != nil {
		info.Error = fmt.Sprintf("process error: %v", err)
		return info
	}

	gfc.processManager.RegisterProcess(process.Process.Pid, process)

	// Wait for process to start
	time.Sleep(2 * time.Second)

	// Get IP and country info
	ip, country, countryCode, err := gfc.getIPInfo(proxyPort)
	if err != nil {
		info.Error = fmt.Sprintf("IP info error: %v", err)
		return info
	}

	info.IP = ip
	info.Country = country
	info.CountryCode = countryCode

	// Get fraud score
	fraudScore, err := gfc.getFraudScore(ip, proxyPort)
	if err != nil {
		// Don't fail completely if fraud score fails
		info.FraudScore = -1
		log.Printf("Warning: Failed to get fraud score for %s: %v", ip, err)
	} else {
		info.FraudScore = fraudScore
	}

	return info
}

func (gfc *GeoFraudChecker) rebuildURLWithRemark(originalURL, remark string) string {
	if strings.HasPrefix(originalURL, "ss://") {
		// Shadowsocks: ss://base64@server:port#remark
		// URL encode the remark for fragment
		parts := strings.Split(originalURL, "#")
		encodedRemark := url.QueryEscape(remark)
		return parts[0] + "#" + encodedRemark

	} else if strings.HasPrefix(originalURL, "vmess://") {
		// VMess: vmess://base64(json)
		// Decode, modify ps field, re-encode
		vmessURL := strings.TrimPrefix(originalURL, "vmess://")
		jsonData, err := base64.StdEncoding.DecodeString(vmessURL)
		if err != nil {
			jsonData, err = base64.RawStdEncoding.DecodeString(vmessURL)
			if err != nil {
				return originalURL // Return original if can't decode
			}
		}

		var vmessConfig map[string]interface{}
		if err := json.Unmarshal(jsonData, &vmessConfig); err != nil {
			return originalURL
		}

		// Update ps (remark) field - keep as plain UTF-8 string (NOT percent-encoded)
		vmessConfig["ps"] = remark

		// Re-encode
		newJSON, err := json.Marshal(vmessConfig)
		if err != nil {
			return originalURL
		}

		newBase64 := base64.StdEncoding.EncodeToString(newJSON)
		return "vmess://" + newBase64

	} else if strings.HasPrefix(originalURL, "vless://") {
		// VLESS: vless://uuid@server:port?params#remark
		// URL encode the remark for fragment
		parts := strings.Split(originalURL, "#")
		encodedRemark := url.QueryEscape(remark)
		return parts[0] + "#" + encodedRemark
	}

	return originalURL
}

func (gfc *GeoFraudChecker) formatURLWithInfo(info *ProxyInfo) string {
	flag := gfc.getCountryFlag(info.CountryCode)

	// Create remark in format: "🔥 🇩🇪 IP-Score: 076 🇩🇪 🔥"
	// IP-Score is inverted: IP-Score = 100 - FraudScore
	// Example: FraudScore 20 -> IP-Score 80, FraudScore 30 -> IP-Score 70
	var remark string
	if info.FraudScore >= 0 {
		// Calculate IP-Score (inverted fraud score)
		ipScore := 100 - info.FraudScore
		// Format score as 3-digit number with leading zeros (e.g., 080, 070, 000)
		remark = fmt.Sprintf("🔥 %s IP-Score: %03d %s 🔥", flag, ipScore, flag)
	} else {
		remark = fmt.Sprintf("🔥 %s IP-Score: N/A %s 🔥", flag, flag)
	}

	// Rebuild URL with new remark
	newURL := gfc.rebuildURLWithRemark(info.URL, remark)

	return newURL
}

func (gfc *GeoFraudChecker) ProcessAllURLs(urls []string) {
	if len(urls) == 0 {
		log.Println("No URLs to process")
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, cleaning up...")
		gfc.Cleanup()
		os.Exit(0)
	}()

	log.Printf("Starting processing %d URLs...", len(urls))

	maxWorkers := gfc.config.MaxWorkers
	if len(urls) < maxWorkers {
		maxWorkers = len(urls)
	}

	urlChan := make(chan string, len(urls))
	resultChan := make(chan *ProxyInfo, len(urls))

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				atomic.AddInt64(&gfc.stats.processed, 1)
				result := gfc.ProcessURL(url)
				resultChan <- result
			}
		}()
	}

	for _, url := range urls {
		urlChan <- url
		atomic.AddInt64(&gfc.stats.total, 1)
	}
	close(urlChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Save results
	gfc.saveResults(resultChan)
}

func (gfc *GeoFraudChecker) saveResults(resultChan chan *ProxyInfo) {
	// Create multiple output files organized by country and quality
	timestamp := time.Now().Format("2006-01-02_15-04-05")

	// Main enriched file
	mainOutputFile := filepath.Join(gfc.config.OutputDir, "enriched_urls.txt")
	mainFile, err := os.Create(mainOutputFile)
	if err != nil {
		log.Fatalf("Failed to create main output file: %v", err)
	}
	defer mainFile.Close()

	// Country-specific directories
	countryDir := filepath.Join(gfc.config.OutputDir, "by_country")
	os.MkdirAll(countryDir, 0755)

	// Quality-based directories
	qualityDir := filepath.Join(gfc.config.OutputDir, "by_quality")
	os.MkdirAll(qualityDir, 0755)

	// Write main file header
	fmt.Fprintf(mainFile, "# Enriched Proxy URLs with Geo-location and Fraud Scores\n")
	fmt.Fprintf(mainFile, "# Generated at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(mainFile, "# Format: Each URL has remark embedded as \"🔥 [Flag] Fraud Score: X [Flag] 🔥\"\n")
	fmt.Fprintf(mainFile, "# The remark is visible in your VPN client\n\n")

	successCount := 0
	failedCount := 0
	countryFiles := make(map[string]*os.File)
	qualityFiles := make(map[string]*os.File)

	// Helper function to get or create country file
	getCountryFile := func(countryCode string) *os.File {
		if file, exists := countryFiles[countryCode]; exists {
			return file
		}

		filename := filepath.Join(countryDir, fmt.Sprintf("%s_%s.txt", strings.ToLower(countryCode), timestamp))
		file, err := os.Create(filename)
		if err != nil {
			log.Printf("Failed to create country file for %s: %v", countryCode, err)
			return nil
		}

		flag := gfc.getCountryFlag(countryCode)
		fmt.Fprintf(file, "# %s %s Proxy URLs\n", flag, countryCode)
		fmt.Fprintf(file, "# Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

		countryFiles[countryCode] = file
		return file
	}

	// Helper function to get or create quality file
	getQualityFile := func(score int) *os.File {
		var quality string
		switch {
		case score >= 0 && score <= 20:
			quality = "excellent"
		case score <= 40:
			quality = "good"
		case score <= 60:
			quality = "medium"
		case score <= 80:
			quality = "poor"
		default:
			quality = "very_poor"
		}

		if file, exists := qualityFiles[quality]; exists {
			return file
		}

		filename := filepath.Join(qualityDir, fmt.Sprintf("%s_%s.txt", quality, timestamp))
		file, err := os.Create(filename)
		if err != nil {
			log.Printf("Failed to create quality file for %s: %v", quality, err)
			return nil
		}

		fmt.Fprintf(file, "# %s Quality Proxy URLs (Fraud Score: %s)\n", strings.ToUpper(quality), getScoreRange(quality))
		fmt.Fprintf(file, "# Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

		qualityFiles[quality] = file
		return file
	}

	// Close all files at the end
	defer func() {
		for _, file := range countryFiles {
			if file != nil {
				file.Close()
			}
		}
		for _, file := range qualityFiles {
			if file != nil {
				file.Close()
			}
		}
	}()

	for result := range resultChan {
		if result.Error != "" {
			failedCount++
			log.Printf("FAILED: %s - %s", truncateString(result.URL, 50), result.Error)
			continue
		}

		successCount++
		formattedURL := gfc.formatURLWithInfo(result)

		// Save to main file (just the URL, remark is embedded in URL)
		fmt.Fprintf(mainFile, "%s\n", formattedURL)

		// Save to country-specific file
		if countryFile := getCountryFile(result.CountryCode); countryFile != nil {
			fmt.Fprintf(countryFile, "%s\n", formattedURL)
		}

		// Save to quality-specific file
		if result.FraudScore >= 0 {
			if qualityFile := getQualityFile(result.FraudScore); qualityFile != nil {
				fmt.Fprintf(qualityFile, "%s\n", formattedURL)
			}
		}

		log.Printf("SUCCESS: %s | %s %s | Score: %d | %.2fs",
			result.IP, gfc.getCountryFlag(result.CountryCode), result.Country,
			result.FraudScore, result.ResponseTime)

		if successCount%10 == 0 {
			mainFile.Sync()
			// Sync country and quality files
			for _, file := range countryFiles {
				if file != nil {
					file.Sync()
				}
			}
			for _, file := range qualityFiles {
				if file != nil {
					file.Sync()
				}
			}
		}
	}

	log.Printf("\n" + strings.Repeat("=", 60))
	log.Printf("🎉 PROCESSING COMPLETED!")
	log.Printf("Total processed: %d", atomic.LoadInt64(&gfc.stats.total))
	log.Printf("✅ Successful: %d", successCount)
	log.Printf("❌ Failed: %d", failedCount)
	if atomic.LoadInt64(&gfc.stats.total) > 0 {
		successRate := float64(successCount) / float64(atomic.LoadInt64(&gfc.stats.total)) * 100
		log.Printf("📊 Success rate: %.1f%%", successRate)
	}
	log.Printf("\n📁 Output files:")
	log.Printf("   Main file: %s", mainOutputFile)
	log.Printf("   By country: %s", countryDir)
	log.Printf("   By quality: %s", qualityDir)
	log.Printf(strings.Repeat("=", 60))
}

func getScoreRange(quality string) string {
	switch quality {
	case "excellent":
		return "0-20"
	case "good":
		return "21-40"
	case "medium":
		return "41-60"
	case "poor":
		return "61-80"
	case "very_poor":
		return "81-100"
	default:
		return "Unknown"
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (gfc *GeoFraudChecker) Cleanup() {
	gfc.processManager.Cleanup()
}

func main() {
	// Get xray path
	xrayPath := getEnvOrDefault("XRAY_PATH", "")

	// Get current directory for path resolution
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}

	if xrayPath == "" || xrayPath == "xray" || xrayPath == "xray.exe" {
		// Try to find xray.exe in current directory
		possiblePaths := []string{
			filepath.Join(currentDir, "xray.exe"),
			filepath.Join(currentDir, "xray"),
		}

		found := false
		for _, path := range possiblePaths {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				xrayPath = path
				found = true
				log.Printf("Found xray at: %s", xrayPath)
				break
			}
		}

		if !found {
			log.Fatalf("Xray executable not found in %s. Please place xray.exe in current directory or set XRAY_PATH to full path", currentDir)
		}
	} else {
		// If path is relative, make it absolute
		if !filepath.IsAbs(xrayPath) {
			xrayPath = filepath.Join(currentDir, xrayPath)
		}

		// Verify the provided path exists
		if info, err := os.Stat(xrayPath); err != nil {
			log.Fatalf("Xray path does not exist: %s (tried: %s)", getEnvOrDefault("XRAY_PATH", ""), xrayPath)
		} else if info.IsDir() {
			log.Fatalf("Xray path is a directory, not a file: %s", xrayPath)
		}
	}

	log.Printf("✓ Using Xray path: %s", xrayPath)

	config := &GeoFraudConfig{
		XrayPath:       xrayPath,
		MaxWorkers:     10, // Lower workers for stability
		Timeout:        30 * time.Second,
		RequestTimeout: 30 * time.Second,
		InputFile:      "../data/working_url/working_all_urls.txt",
		OutputDir:      "../data/enriched_urls",
		StartPort:      30000,
		EndPort:        31000,
	}

	// Create output directory
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	checker := NewGeoFraudChecker(config)
	defer checker.Cleanup()

	// Load URLs
	urls, err := checker.LoadURLsFromFile()
	if err != nil {
		log.Fatalf("Failed to load URLs: %v", err)
	}

	// Process all URLs
	checker.ProcessAllURLs(urls)

	log.Println("Processing completed!")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
