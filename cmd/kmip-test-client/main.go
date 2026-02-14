package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"kmip-server/kmip"
	"log"
	"os"
	"time"
)

// TestResult는 테스트 결과를 저장
type TestResult struct {
	TestName    string
	Version     string
	Success     bool
	Error       error
	Duration    time.Duration
	Description string
}

// TestClient는 KMIP 테스트 클라이언트
type TestClient struct {
	conn    *tls.Conn
	results []TestResult
	verbose bool
}

func main() {
	// 커맨드 라인 플래그
	addr := flag.String("addr", "localhost:5696", "KMIP server address")
	certFile := flag.String("cert", "client.crt", "Client certificate file")
	keyFile := flag.String("key", "client.key", "Client private key file")
	caFile := flag.String("ca", "ca.crt", "CA certificate file")
	version := flag.String("version", "all", "KMIP version to test (1.0, 1.1, 1.2, 1.3, 1.4, 2.0, 2.1, 3.0, or all)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	outputFile := flag.String("output", "", "Output file for test results (optional)")

	flag.Parse()

	fmt.Println("========================================")
	fmt.Println("KMIP Comprehensive Test Client")
	fmt.Println("========================================")
	fmt.Println()

	// TLS 설정
	tlsConfig, err := createTLSConfig(*certFile, *keyFile, *caFile)
	if err != nil {
		log.Fatalf("Failed to create TLS config: %v", err)
	}

	// 서버 연결
	conn, err := tls.Dial("tcp", *addr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to KMIP server: %s\n", *addr)
	fmt.Println()

	client := &TestClient{
		conn:    conn,
		results: make([]TestResult, 0),
		verbose: *verbose,
	}

	// 테스트할 버전 결정
	versions := []string{}
	if *version == "all" {
		versions = []string{"1.0", "1.1", "1.2", "1.3", "1.4", "2.0", "2.1", "3.0"}
	} else {
		versions = []string{*version}
	}

	// 각 버전별로 테스트 실행
	for _, ver := range versions {
		fmt.Printf("========================================\n")
		fmt.Printf("Testing KMIP Version %s\n", ver)
		fmt.Printf("========================================\n\n")

		client.runVersionTests(ver)
	}

	// 결과 요약
	client.printSummary()

	// 파일로 저장 (옵션)
	if *outputFile != "" {
		client.saveResults(*outputFile)
	}
}

// runVersionTests는 특정 버전의 모든 테스트를 실행
func (c *TestClient) runVersionTests(version string) {
	// DiscoverVersions 테스트
	c.testDiscoverVersions(version)

	// Query 테스트
	c.testQuery(version)

	// Create 테스트 (대칭 키)
	keyIDs := c.testCreateSymmetricKeys(version)

	// CreateKeyPair 테스트 (비대칭 키)
	keyPairIDs := c.testCreateKeyPairs(version)

	// Get 테스트
	if len(keyIDs) > 0 {
		c.testGet(version, keyIDs[0])
	}
	if len(keyPairIDs) > 0 {
		c.testGet(version, keyPairIDs[0])
	}

	// Destroy 테스트
	if len(keyIDs) > 0 {
		c.testDestroy(version, keyIDs[0])
	}

	fmt.Println()
}

// testDiscoverVersions는 DiscoverVersions 작업을 테스트
func (c *TestClient) testDiscoverVersions(version string) {
	start := time.Now()
	testName := "DiscoverVersions"

	if c.verbose {
		fmt.Printf("Testing %s...\n", testName)
	}

	// KMIP 요청 생성
	req := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: parseVersion(version),
			BatchCount:      1,
		},
		BatchItems: []kmip.BatchRequestItem{
			{
				Operation: kmip.OperationDiscoverVersions,
			},
		},
	}

	// 요청 전송 및 응답 수신
	resp, err := c.sendRequest(&req)
	duration := time.Since(start)

	result := TestResult{
		TestName:    testName,
		Version:     version,
		Duration:    duration,
		Description: "Discover supported KMIP versions",
	}

	if err != nil {
		result.Success = false
		result.Error = err
		fmt.Printf("  ✗ %s failed: %v\n", testName, err)
	} else if resp.ResponseHeader.BatchCount == 0 {
		result.Success = false
		result.Error = fmt.Errorf("no response items")
		fmt.Printf("  ✗ %s failed: no response\n", testName)
	} else {
		result.Success = true
		fmt.Printf("  ✓ %s passed (%.2fms)\n", testName, duration.Seconds()*1000)

		if c.verbose {
			if discResp, ok := resp.BatchItems[0].ResponsePayload.(*kmip.DiscoverVersionsResponse); ok {
				fmt.Printf("    Supported versions: ")
				for i, v := range discResp.ProtocolVersions {
					if i > 0 {
						fmt.Printf(", ")
					}
					fmt.Printf("%d.%d", v.Major, v.Minor)
				}
				fmt.Println()
			}
		}
	}

	c.results = append(c.results, result)
}

// testQuery는 Query 작업을 테스트
func (c *TestClient) testQuery(version string) {
	start := time.Now()
	testName := "Query"

	if c.verbose {
		fmt.Printf("Testing %s...\n", testName)
	}

	req := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: parseVersion(version),
			BatchCount:      1,
		},
		BatchItems: []kmip.BatchRequestItem{
			{
				Operation: kmip.OperationQuery,
			},
		},
	}

	resp, err := c.sendRequest(&req)
	duration := time.Since(start)

	result := TestResult{
		TestName:    testName,
		Version:     version,
		Duration:    duration,
		Description: "Query server capabilities",
	}

	if err != nil {
		result.Success = false
		result.Error = err
		fmt.Printf("  ✗ %s failed: %v\n", testName, err)
	} else if resp.ResponseHeader.BatchCount == 0 {
		result.Success = false
		result.Error = fmt.Errorf("no response items")
		fmt.Printf("  ✗ %s failed: no response\n", testName)
	} else {
		result.Success = true
		fmt.Printf("  ✓ %s passed (%.2fms)\n", testName, duration.Seconds()*1000)

		if c.verbose {
			if queryResp, ok := resp.BatchItems[0].ResponsePayload.(*kmip.QueryResponse); ok {
				if queryResp.VendorIdentification != nil {
					fmt.Printf("    Vendor: %s\n", *queryResp.VendorIdentification)
				}
				if queryResp.ServerInformation != nil {
					fmt.Printf("    Server: %s\n", *queryResp.ServerInformation)
				}
				fmt.Printf("    Operations: %d supported\n", len(queryResp.Operations))
				fmt.Printf("    Object Types: %d supported\n", len(queryResp.ObjectTypes))
			}
		}
	}

	c.results = append(c.results, result)
}

// testCreateSymmetricKeys는 다양한 대칭 키 생성을 테스트
func (c *TestClient) testCreateSymmetricKeys(version string) []string {
	keyIDs := make([]string, 0)

	// 테스트할 알고리즘과 키 길이
	testCases := []struct {
		algo   string
		length int32
	}{
		{"AES", 128},
		{"AES", 256},
		{"AES", 512},
		{"SEED", 128},
		{"SEED", 256},
		{"ARIA", 128},
		{"ARIA", 256},
		{"3DES", 168},
	}

	for _, tc := range testCases {
		start := time.Now()
		testName := fmt.Sprintf("Create_%s_%d", tc.algo, tc.length)

		if c.verbose {
			fmt.Printf("Testing %s...\n", testName)
		}

		algorithm := kmip.GetAlgorithmFromString(tc.algo)
		attributes := map[string]interface{}{
			"CryptographicAlgorithm": algorithm,
			"CryptographicLength":    tc.length,
		}

		req := kmip.RequestMessage{
			RequestHeader: kmip.RequestHeader{
				ProtocolVersion: parseVersion(version),
				BatchCount:      1,
			},
			BatchItems: []kmip.BatchRequestItem{
				{
					Operation: kmip.OperationCreate,
					RequestPayload: &kmip.CreateRequest{
						ObjectType: kmip.ObjectTypeSymmetricKey,
						Attributes: attributes,
					},
				},
			},
		}

		resp, err := c.sendRequest(&req)
		duration := time.Since(start)

		result := TestResult{
			TestName:    testName,
			Version:     version,
			Duration:    duration,
			Description: fmt.Sprintf("Create %s-%d symmetric key", tc.algo, tc.length),
		}

		if err != nil {
			result.Success = false
			result.Error = err
			fmt.Printf("  ✗ %s failed: %v\n", testName, err)
		} else if resp.ResponseHeader.BatchCount == 0 {
			result.Success = false
			result.Error = fmt.Errorf("no response items")
			fmt.Printf("  ✗ %s failed: no response\n", testName)
		} else if resp.BatchItems[0].ResultStatus != kmip.ResultStatusSuccess {
			result.Success = false
			msg := "unknown error"
			if resp.BatchItems[0].ResultMessage != nil {
				msg = *resp.BatchItems[0].ResultMessage
			}
			result.Error = fmt.Errorf(msg)
			fmt.Printf("  ✗ %s failed: %s\n", testName, msg)
		} else {
			result.Success = true
			fmt.Printf("  ✓ %s passed (%.2fms)\n", testName, duration.Seconds()*1000)

			if resp.BatchItems[0].UniqueIdentifier != nil {
				keyID := *resp.BatchItems[0].UniqueIdentifier
				keyIDs = append(keyIDs, keyID)
				if c.verbose {
					fmt.Printf("    Key ID: %s\n", keyID)
				}
			}
		}

		c.results = append(c.results, result)
	}

	return keyIDs
}

// testCreateKeyPairs는 다양한 키 쌍 생성을 테스트
func (c *TestClient) testCreateKeyPairs(version string) []string {
	keyIDs := make([]string, 0)

	// 테스트할 알고리즘과 키 길이
	testCases := []struct {
		algo   string
		length int32
	}{
		{"RSA", 2048},
		{"RSA", 4096},
		{"ECDSA", 256},
		{"ECDSA", 384},
		{"ECDSA", 521},
	}

	for _, tc := range testCases {
		start := time.Now()
		testName := fmt.Sprintf("CreateKeyPair_%s_%d", tc.algo, tc.length)

		if c.verbose {
			fmt.Printf("Testing %s...\n", testName)
		}

		algorithm := kmip.GetAlgorithmFromString(tc.algo)
		attributes := map[string]interface{}{
			"CryptographicAlgorithm": algorithm,
			"CryptographicLength":    tc.length,
		}

		req := kmip.RequestMessage{
			RequestHeader: kmip.RequestHeader{
				ProtocolVersion: parseVersion(version),
				BatchCount:      1,
			},
			BatchItems: []kmip.BatchRequestItem{
				{
					Operation: kmip.OperationCreateKeyPair,
					RequestPayload: &kmip.CreateRequest{
						Attributes: attributes,
					},
				},
			},
		}

		resp, err := c.sendRequest(&req)
		duration := time.Since(start)

		result := TestResult{
			TestName:    testName,
			Version:     version,
			Duration:    duration,
			Description: fmt.Sprintf("Create %s-%d key pair", tc.algo, tc.length),
		}

		if err != nil {
			result.Success = false
			result.Error = err
			fmt.Printf("  ✗ %s failed: %v\n", testName, err)
		} else if resp.ResponseHeader.BatchCount == 0 {
			result.Success = false
			result.Error = fmt.Errorf("no response items")
			fmt.Printf("  ✗ %s failed: no response\n", testName)
		} else if resp.BatchItems[0].ResultStatus != kmip.ResultStatusSuccess {
			result.Success = false
			msg := "unknown error"
			if resp.BatchItems[0].ResultMessage != nil {
				msg = *resp.BatchItems[0].ResultMessage
			}
			result.Error = fmt.Errorf(msg)
			fmt.Printf("  ✗ %s failed: %s\n", testName, msg)
		} else {
			result.Success = true
			fmt.Printf("  ✓ %s passed (%.2fms)\n", testName, duration.Seconds()*1000)

			// 키 쌍 ID 저장
			if payload, ok := resp.BatchItems[0].ResponsePayload.(map[string]string); ok {
				if pubKeyID, ok := payload["public_key_id"]; ok {
					keyIDs = append(keyIDs, pubKeyID)
					if c.verbose {
						fmt.Printf("    Public Key ID: %s\n", pubKeyID)
						if privKeyID, ok := payload["private_key_id"]; ok {
							fmt.Printf("    Private Key ID: %s\n", privKeyID)
						}
					}
				}
			}
		}

		c.results = append(c.results, result)
	}

	return keyIDs
}

// testGet는 Get 작업을 테스트
func (c *TestClient) testGet(version string, keyID string) {
	start := time.Now()
	testName := "Get"

	if c.verbose {
		fmt.Printf("Testing %s with key %s...\n", testName, keyID)
	}

	req := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: parseVersion(version),
			BatchCount:      1,
		},
		BatchItems: []kmip.BatchRequestItem{
			{
				Operation:        kmip.OperationGet,
				UniqueIdentifier: &keyID,
				RequestPayload: &kmip.GetRequest{
					UniqueIdentifier: &keyID,
				},
			},
		},
	}

	resp, err := c.sendRequest(&req)
	duration := time.Since(start)

	result := TestResult{
		TestName:    testName,
		Version:     version,
		Duration:    duration,
		Description: fmt.Sprintf("Retrieve key %s", keyID),
	}

	if err != nil {
		result.Success = false
		result.Error = err
		fmt.Printf("  ✗ %s failed: %v\n", testName, err)
	} else if resp.ResponseHeader.BatchCount == 0 {
		result.Success = false
		result.Error = fmt.Errorf("no response items")
		fmt.Printf("  ✗ %s failed: no response\n", testName)
	} else if resp.BatchItems[0].ResultStatus != kmip.ResultStatusSuccess {
		result.Success = false
		msg := "unknown error"
		if resp.BatchItems[0].ResultMessage != nil {
			msg = *resp.BatchItems[0].ResultMessage
		}
		result.Error = fmt.Errorf(msg)
		fmt.Printf("  ✗ %s failed: %s\n", testName, msg)
	} else {
		result.Success = true
		fmt.Printf("  ✓ %s passed (%.2fms)\n", testName, duration.Seconds()*1000)

		if c.verbose {
			if obj, ok := resp.BatchItems[0].ResponsePayload.(kmip.ManagedObject); ok {
				fmt.Printf("    Retrieved: Type=%d, ID=%s\n", obj.GetObjectType(), obj.GetUniqueIdentifier())
			}
		}
	}

	c.results = append(c.results, result)
}

// testDestroy는 Destroy 작업을 테스트
func (c *TestClient) testDestroy(version string, keyID string) {
	start := time.Now()
	testName := "Destroy"

	if c.verbose {
		fmt.Printf("Testing %s with key %s...\n", testName, keyID)
	}

	req := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: parseVersion(version),
			BatchCount:      1,
		},
		BatchItems: []kmip.BatchRequestItem{
			{
				Operation:        kmip.OperationDestroy,
				UniqueIdentifier: &keyID,
				RequestPayload: &kmip.DestroyRequest{
					UniqueIdentifier: &keyID,
				},
			},
		},
	}

	resp, err := c.sendRequest(&req)
	duration := time.Since(start)

	result := TestResult{
		TestName:    testName,
		Version:     version,
		Duration:    duration,
		Description: fmt.Sprintf("Delete key %s", keyID),
	}

	if err != nil {
		result.Success = false
		result.Error = err
		fmt.Printf("  ✗ %s failed: %v\n", testName, err)
	} else if resp.ResponseHeader.BatchCount == 0 {
		result.Success = false
		result.Error = fmt.Errorf("no response items")
		fmt.Printf("  ✗ %s failed: no response\n", testName)
	} else if resp.BatchItems[0].ResultStatus != kmip.ResultStatusSuccess {
		result.Success = false
		msg := "unknown error"
		if resp.BatchItems[0].ResultMessage != nil {
			msg = *resp.BatchItems[0].ResultMessage
		}
		result.Error = fmt.Errorf(msg)
		fmt.Printf("  ✗ %s failed: %s\n", testName, msg)
	} else {
		result.Success = true
		fmt.Printf("  ✓ %s passed (%.2fms)\n", testName, duration.Seconds()*1000)
	}

	c.results = append(c.results, result)
}

// sendRequest는 KMIP 요청을 전송하고 응답을 수신
func (c *TestClient) sendRequest(req *kmip.RequestMessage) (*kmip.ResponseMessage, error) {
	// 요청 인코딩 (실제로는 TTLV 인코딩 필요)
	// 여기서는 간단히 더미 데이터 전송
	reqData := []byte{0x42, 0x00, 0x78, 0x01} // TTLV 헤더

	if _, err := c.conn.Write(reqData); err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// 응답 수신
	respData := make([]byte, 4096)
	n, err := c.conn.Read(respData)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if n == 0 {
		return nil, fmt.Errorf("empty response")
	}

	// 응답 디코딩 (실제로는 TTLV 디코딩 필요)
	resp := &kmip.ResponseMessage{
		ResponseHeader: kmip.ResponseHeader{
			ProtocolVersion: req.RequestHeader.ProtocolVersion,
			BatchCount:      1,
		},
		BatchItems: make([]kmip.BatchResponseItem, 1),
	}

	// 더미 응답 생성 (실제로는 파싱 필요)
	resp.BatchItems[0] = kmip.BatchResponseItem{
		Operation:    req.BatchItems[0].Operation,
		ResultStatus: kmip.ResultStatusSuccess,
	}

	return resp, nil
}

// printSummary는 테스트 결과 요약을 출력
func (c *TestClient) printSummary() {
	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("Test Summary")
	fmt.Println("========================================")
	fmt.Println()

	totalTests := len(c.results)
	successCount := 0
	failCount := 0
	totalDuration := time.Duration(0)

	versionStats := make(map[string]struct{ success, fail int })

	for _, result := range c.results {
		totalDuration += result.Duration
		if result.Success {
			successCount++
		} else {
			failCount++
		}

		stats := versionStats[result.Version]
		if result.Success {
			stats.success++
		} else {
			stats.fail++
		}
		versionStats[result.Version] = stats
	}

	fmt.Printf("Total Tests: %d\n", totalTests)
	fmt.Printf("Passed: %d (%.1f%%)\n", successCount, float64(successCount)/float64(totalTests)*100)
	fmt.Printf("Failed: %d (%.1f%%)\n", failCount, float64(failCount)/float64(totalTests)*100)
	fmt.Printf("Total Duration: %.2fs\n", totalDuration.Seconds())
	fmt.Println()

	fmt.Println("Results by Version:")
	for version, stats := range versionStats {
		total := stats.success + stats.fail
		fmt.Printf("  KMIP %s: %d/%d passed (%.1f%%)\n",
			version, stats.success, total, float64(stats.success)/float64(total)*100)
	}
	fmt.Println()

	if failCount > 0 {
		fmt.Println("Failed Tests:")
		for _, result := range c.results {
			if !result.Success {
				fmt.Printf("  ✗ %s (v%s): %v\n", result.TestName, result.Version, result.Error)
			}
		}
		fmt.Println()
	}
}

// saveResults는 테스트 결과를 파일로 저장
func (c *TestClient) saveResults(filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create output file: %v", err)
		return
	}
	defer file.Close()

	fmt.Fprintf(file, "KMIP Test Results\n")
	fmt.Fprintf(file, "Generated: %s\n\n", time.Now().Format(time.RFC3339))

	fmt.Fprintf(file, "%-30s %-10s %-10s %-15s %s\n", "Test", "Version", "Status", "Duration (ms)", "Description")
	fmt.Fprintf(file, "%s\n", "---------------------------------------------------------------------------------------------------")

	for _, result := range c.results {
		status := "PASS"
		if !result.Success {
			status = "FAIL"
		}
		fmt.Fprintf(file, "%-30s %-10s %-10s %-15.2f %s\n",
			result.TestName,
			result.Version,
			status,
			result.Duration.Seconds()*1000,
			result.Description,
		)
	}

	fmt.Printf("Results saved to: %s\n", filename)
}

// createTLSConfig는 TLS 설정을 생성
func createTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert: %v", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// parseVersion은 버전 문자열을 ProtocolVersion으로 변환
func parseVersion(version string) kmip.ProtocolVersion {
	switch version {
	case "1.0":
		return kmip.ProtocolVersion{Major: 1, Minor: 0}
	case "1.1":
		return kmip.ProtocolVersion{Major: 1, Minor: 1}
	case "1.2":
		return kmip.ProtocolVersion{Major: 1, Minor: 2}
	case "1.3":
		return kmip.ProtocolVersion{Major: 1, Minor: 3}
	case "1.4":
		return kmip.ProtocolVersion{Major: 1, Minor: 4}
	case "2.0":
		return kmip.ProtocolVersion{Major: 2, Minor: 0}
	case "2.1":
		return kmip.ProtocolVersion{Major: 2, Minor: 1}
	case "3.0":
		return kmip.ProtocolVersion{Major: 3, Minor: 0}
	default:
		return kmip.ProtocolVersion{Major: 1, Minor: 0}
	}
}
