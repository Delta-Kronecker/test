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
}

func NewGeoFraudChecker(config *GeoFraudConfig) *GeoFraudChecker {
	gfc := &GeoFraudChecker{
		config:         config,
		portManager:    NewPortManager(config.StartPort, config.EndPort),
		processManager: NewProcessManager(),
	}
	return gfc
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
	proxyURL = strings.TrimPrefix(proxyURL, "ss://")

	parts := strings.Split(proxyURL, "#")
	proxyURL = parts[0]

	authServer := strings.Split(proxyURL, "@")
	if len(authServer) != 2 {
		return nil, fmt.Errorf("invalid shadowsocks URL format")
	}

	authDecoded, err := base64.StdEncoding.DecodeString(authServer[0])
	if err != nil {
		authDecoded, err = base64.RawStdEncoding.DecodeString(authServer[0])
		if err != nil {
			return nil, fmt.Errorf("failed to decode auth: %v", err)
		}
	}

	authParts := strings.SplitN(string(authDecoded), ":", 2)
	if len(authParts) != 2 {
		return nil, fmt.Errorf("invalid auth format")
	}
	method := authParts[0]
	password := authParts[1]

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
	proxyURL = strings.TrimPrefix(proxyURL, "vmess://")

	jsonData, err := base64.StdEncoding.DecodeString(proxyURL)
	if err != nil {
		jsonData, err = base64.RawStdEncoding.DecodeString(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to decode vmess: %v", err)
		}
	}

	var vmessConfig map[string]interface{}
	if err := json.Unmarshal(jsonData, &vmessConfig); err != nil {
		return nil, fmt.Errorf("failed to parse vmess json: %v", err)
	}

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

	if getString(vmessConfig, "tls") == "tls" {
		streamSettings := outbound["streamSettings"].(map[string]interface{})
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"allowInsecure": true,
			"serverName":    getString(vmessConfig, "sni"),
		}
	}

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
	proxyURL = strings.TrimPrefix(proxyURL, "vless://")

	parts := strings.Split(proxyURL, "#")
	proxyURL = parts[0]

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

	// Create log files for debugging in CI environments
	var logFileName string
	logFile, err := os.CreateTemp("", "xray-log-*.txt")
	if err == nil {
		logFileName = logFile.Name()
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		// Note: logFile will be closed when process exits
	}

	if err := cmd.Start(); err != nil {
		if logFileName != "" {
			return nil, fmt.Errorf("failed to start xray (logs: %s): %v", logFileName, err)
		}
		return nil, err
	}

	// Give the process a moment to fail if there's an immediate error
	time.Sleep(200 * time.Millisecond)

	// Check if process is still running
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		if logFileName != "" {
			// Try to read the log for debugging
			if logContent, readErr := os.ReadFile(logFileName); readErr == nil && len(logContent) > 0 {
				return nil, fmt.Errorf("xray process exited immediately. Log: %s", string(logContent))
			}
			return nil, fmt.Errorf("xray process exited immediately (check log: %s)", logFileName)
		}
		return nil, fmt.Errorf("xray process exited immediately")
	}

	return cmd, nil
}

func (gfc *GeoFraudChecker) getIPInfo(proxyPort int) (string, string, string, error) {
	// Detect CI environment and adjust timeouts accordingly
	ciWaitTime := 1 * time.Second
	dialTimeout := 5 * time.Second
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		ciWaitTime = 3 * time.Second
		dialTimeout = 10 * time.Second
		log.Printf("CI environment detected, using extended timeouts")
	}

	time.Sleep(ciWaitTime)

	// Try multiple times to connect to the proxy
	var conn net.Conn
	var err error
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), dialTimeout)
		if err == nil {
			conn.Close()
			break
		}
		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	if err != nil {
		return "", "", "", fmt.Errorf("proxy not responsive after %d attempts: %v", maxRetries, err)
	}

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

	resp, err := client.Get("https://api.ipify.org?format=json")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		if json.Unmarshal(body, &result) == nil {
			if ip, ok := result["ip"].(string); ok {
				country, countryCode := gfc.getCountryFromIPAPI(client, ip)
				return ip, country, countryCode, nil
			}
		}
	}

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

			country, countryCode := gfc.getCountryFromIPAPI(client, ip)
			return ip, country, countryCode, nil
		}
	}

	return "", "", "", fmt.Errorf("failed to extract IP")
}

func (gfc *GeoFraudChecker) getCountryFromIPAPI(client *http.Client, ip string) (string, string) {
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

	var ok bool
	proxyPort, ok = gfc.portManager.GetAvailablePort()
	if !ok || proxyPort == 0 {
		info.Error = "no available port"
		return info
	}

	var err error
	configFile, err = gfc.createXrayConfig(proxyURL, proxyPort)
	if err != nil {
		info.Error = fmt.Sprintf("config error: %v", err)
		return info
	}

	process, err = gfc.startXrayProcess(configFile)
	if err != nil {
		info.Error = fmt.Sprintf("process error: %v", err)
		return info
	}

	gfc.processManager.RegisterProcess(process.Process.Pid, process)

	// Wait for Xray to fully initialize - longer in CI environments
	waitTime := 2 * time.Second
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		waitTime = 5 * time.Second
	}
	time.Sleep(waitTime)

	// Verify process is still running before attempting connection
	if process.ProcessState != nil && process.ProcessState.Exited() {
		info.Error = "xray process died after startup"
		return info
	}

	ip, country, countryCode, err := gfc.getIPInfo(proxyPort)
	if err != nil {
		info.Error = fmt.Sprintf("IP info error: %v", err)
		return info
	}

	info.IP = ip
	info.Country = country
	info.CountryCode = countryCode

	return info
}

func (gfc *GeoFraudChecker) rebuildURLWithRemark(originalURL, remark string) string {
	if strings.HasPrefix(originalURL, "ss://") {
		parts := strings.Split(originalURL, "#")
		encodedRemark := url.QueryEscape(remark)
		return parts[0] + "#" + encodedRemark

	} else if strings.HasPrefix(originalURL, "vmess://") {
		vmessURL := strings.TrimPrefix(originalURL, "vmess://")
		jsonData, err := base64.StdEncoding.DecodeString(vmessURL)
		if err != nil {
			jsonData, err = base64.RawStdEncoding.DecodeString(vmessURL)
			if err != nil {
				return originalURL
			}
		}

		var vmessConfig map[string]interface{}
		if err := json.Unmarshal(jsonData, &vmessConfig); err != nil {
			return originalURL
		}

		vmessConfig["ps"] = remark

		newJSON, err := json.Marshal(vmessConfig)
		if err != nil {
			return originalURL
		}

		newBase64 := base64.StdEncoding.EncodeToString(newJSON)
		return "vmess://" + newBase64

	} else if strings.HasPrefix(originalURL, "vless://") {
		parts := strings.Split(originalURL, "#")
		encodedRemark := url.QueryEscape(remark)
		return parts[0] + "#" + encodedRemark
	}

	return originalURL
}

func (gfc *GeoFraudChecker) formatURLWithInfo(info *ProxyInfo) string {
	remark := fmt.Sprintf("🔥 %s 🔥", info.Country)
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

	gfc.saveResults(resultChan)
}

func (gfc *GeoFraudChecker) saveResults(resultChan chan *ProxyInfo) {
	timestamp := time.Now().Format("2006-01-02_15-04-05")

	mainOutputFile := filepath.Join(gfc.config.OutputDir, "enriched_urls.txt")
	mainFile, err := os.Create(mainOutputFile)
	if err != nil {
		log.Fatalf("Failed to create main output file: %v", err)
	}
	defer mainFile.Close()

	countryDir := filepath.Join(gfc.config.OutputDir, "by_country")
	os.MkdirAll(countryDir, 0755)

	fmt.Fprintf(mainFile, "# Enriched Proxy URLs with Geo-location\n")
	fmt.Fprintf(mainFile, "# Generated at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(mainFile, "# Format: Each URL has remark embedded as \"🔥 Country 🔥\"\n\n")

	successCount := 0
	failedCount := 0
	countryFiles := make(map[string]*os.File)

	getCountryFile := func(countryCode, countryName string) *os.File {
		if file, exists := countryFiles[countryCode]; exists {
			return file
		}

		filename := filepath.Join(countryDir, fmt.Sprintf("%s_%s.txt", strings.ToLower(countryCode), timestamp))
		file, err := os.Create(filename)
		if err != nil {
			log.Printf("Failed to create country file for %s: %v", countryCode, err)
			return nil
		}

		fmt.Fprintf(file, "# %s Proxy URLs\n", countryName)
		fmt.Fprintf(file, "# Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

		countryFiles[countryCode] = file
		return file
	}

	defer func() {
		for _, file := range countryFiles {
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

		fmt.Fprintf(mainFile, "%s\n", formattedURL)

		if countryFile := getCountryFile(result.CountryCode, result.Country); countryFile != nil {
			fmt.Fprintf(countryFile, "%s\n", formattedURL)
		}

		log.Printf("SUCCESS: %s | %s | %.2fs",
			result.IP, result.Country, result.ResponseTime)

		if successCount%10 == 0 {
			mainFile.Sync()
			for _, file := range countryFiles {
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
	log.Printf(strings.Repeat("=", 60))
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
	xrayPath := getEnvOrDefault("XRAY_PATH", "")

	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}

	if xrayPath == "" || xrayPath == "xray" || xrayPath == "xray.exe" {
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
		if !filepath.IsAbs(xrayPath) {
			xrayPath = filepath.Join(currentDir, xrayPath)
		}

		if info, err := os.Stat(xrayPath); err != nil {
			log.Fatalf("Xray path does not exist: %s (tried: %s)", getEnvOrDefault("XRAY_PATH", ""), xrayPath)
		} else if info.IsDir() {

			log.Fatalf("Xray path is a directory, not a file: %s", xrayPath)
		}
	}

	log.Printf("✓ Using Xray path: %s", xrayPath)

	// Detect CI environment and adjust configuration
	maxWorkers := 10
	timeout := 30 * time.Second
	requestTimeout := 30 * time.Second

	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		log.Println("🔧 CI environment detected - adjusting configuration for reliability")
		maxWorkers = 3 // Reduce parallelism in CI to avoid resource exhaustion
		timeout = 60 * time.Second
		requestTimeout = 45 * time.Second
		log.Printf("   Max workers: %d (reduced for CI)", maxWorkers)
		log.Printf("   Timeouts: %v request, %v overall", requestTimeout, timeout)
	}

	config := &GeoFraudConfig{
		XrayPath:       xrayPath,
		MaxWorkers:     maxWorkers,
		Timeout:        timeout,
		RequestTimeout: requestTimeout,
		InputFile:      "./data/working_url/working_all_urls.txt",
		OutputDir:      "./data/enriched_urls",
		StartPort:      30000,
		EndPort:        31000,
	}

	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	checker := NewGeoFraudChecker(config)
	defer checker.Cleanup()

	urls, err := checker.LoadURLsFromFile()
	if err != nil {
		log.Fatalf("Failed to load URLs: %v", err)
	}

	checker.ProcessAllURLs(urls)

	log.Println("Processing completed!")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
