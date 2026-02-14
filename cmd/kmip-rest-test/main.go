package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// 색상 정의
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

// TestResult는 테스트 결과
type TestResult struct {
	Category    string
	TestName    string
	Success     bool
	Duration    time.Duration
	Error       string
	Response    interface{}
	Description string
}

// TestSuite는 테스트 스위트
type TestSuite struct {
	baseURL string
	client  *http.Client
	results []TestResult
	verbose bool
}

func main() {
	addr := flag.String("addr", "http://localhost:9090", "REST API server address")
	verbose := flag.Bool("verbose", false, "Verbose output")
	category := flag.String("category", "all", "Test category (all, basic, symmetric, asymmetric, management)")
	output := flag.String("output", "", "Output file for results (JSON format)")

	flag.Parse()

	fmt.Printf("%s========================================%s\n", colorBlue, colorReset)
	fmt.Printf("%sKMIP REST API Comprehensive Test Suite%s\n", colorBlue, colorReset)
	fmt.Printf("%s========================================%s\n\n", colorBlue, colorReset)

	suite := &TestSuite{
		baseURL: *addr,
		client:  &http.Client{Timeout: 30 * time.Second},
		results: make([]TestResult, 0),
		verbose: *verbose,
	}

	// 테스트 실행
	switch *category {
	case "all":
		suite.runAllTests()
	case "basic":
		suite.runBasicTests()
	case "symmetric":
		suite.runSymmetricKeyTests()
	case "asymmetric":
		suite.runAsymmetricKeyTests()
	case "management":
		suite.runManagementTests()
	default:
		fmt.Printf("%sUnknown category: %s%s\n", colorRed, *category, colorReset)
		os.Exit(1)
	}

	// 결과 출력
	suite.printSummary()

	// 파일 저장
	if *output != "" {
		suite.saveResults(*output)
	}
}

// runAllTests는 모든 테스트를 실행
func (s *TestSuite) runAllTests() {
	s.runBasicTests()
	s.runSymmetricKeyTests()
	s.runAsymmetricKeyTests()
	s.runManagementTests()
}

// runBasicTests는 기본 기능 테스트
func (s *TestSuite) runBasicTests() {
	fmt.Printf("\n%s=== Basic Tests ===%s\n\n", colorCyan, colorReset)

	s.testHealthCheck()
	s.testAPIRoot()
	s.testServerInfo()
	s.testSupportedVersions()
}

// runSymmetricKeyTests는 대칭 키 테스트
func (s *TestSuite) runSymmetricKeyTests() {
	fmt.Printf("\n%s=== Symmetric Key Tests ===%s\n\n", colorCyan, colorReset)

	algorithms := []struct {
		name   string
		length int
	}{
		{"AES", 128},
		{"AES", 192},
		{"AES", 256},
		{"AES", 512},
		{"SEED", 128},
		{"SEED", 256},
		{"SEED", 512},
		{"ARIA", 128},
		{"ARIA", 192},
		{"ARIA", 256},
		{"ARIA", 512},
		{"3DES", 168},
	}

	keyIDs := make([]string, 0)

	for _, algo := range algorithms {
		keyID := s.testCreateSymmetricKey(algo.name, algo.length)
		if keyID != "" {
			keyIDs = append(keyIDs, keyID)
		}
	}

	// 키 조회 및 삭제 테스트
	if len(keyIDs) > 0 {
		s.testGetKey(keyIDs[0])
		s.testListKeys()
		s.testDeleteKey(keyIDs[0])
	}
}

// runAsymmetricKeyTests는 비대칭 키 테스트
func (s *TestSuite) runAsymmetricKeyTests() {
	fmt.Printf("\n%s=== Asymmetric Key Tests ===%s\n\n", colorCyan, colorReset)

	testCases := []struct {
		algo   string
		length int
	}{
		{"RSA", 1024},
		{"RSA", 2048},
		{"RSA", 3072},
		{"RSA", 4096},
		{"ECDSA", 192},
		{"ECDSA", 224},
		{"ECDSA", 256},
		{"ECDSA", 384},
		{"ECDSA", 521},
	}

	for _, tc := range testCases {
		s.testCreateKeyPair(tc.algo, tc.length)
	}
}

// runManagementTests는 관리 기능 테스트
func (s *TestSuite) runManagementTests() {
	fmt.Printf("\n%s=== Management Tests ===%s\n\n", colorCyan, colorReset)

	// 여러 키 생성
	keyIDs := make([]string, 0)
	for i := 0; i < 5; i++ {
		keyID := s.testCreateSymmetricKey("AES", 256)
		if keyID != "" {
			keyIDs = append(keyIDs, keyID)
		}
	}

	// 목록 조회
	s.testListKeys()

	// AlternateName으로 키 등록
	if len(keyIDs) > 0 {
		s.testAddAlternateName(keyIDs[0], "test-alternate-name")
		s.testLocateByAlternateName("test-alternate-name")
	}

	// 속성 관리 테스트
	if len(keyIDs) > 1 {
		s.testGetAttributes(keyIDs[1])
		s.testAddAttributes(keyIDs[1])
		s.testModifyAttributes(keyIDs[1])
		s.testDeleteAttribute(keyIDs[1])
	}

	// Rekey 테스트
	if len(keyIDs) > 2 {
		s.testRekey(keyIDs[2])
	}

	// 키 등록 테스트
	s.testRegisterKey()

	// 일괄 삭제
	for _, keyID := range keyIDs {
		s.testDeleteKey(keyID)
	}

	// 최종 목록 확인
	s.testListKeys()
}

// testHealthCheck는 헬스체크 테스트
func (s *TestSuite) testHealthCheck() {
	start := time.Now()
	resp, err := s.client.Get(fmt.Sprintf("%s/health", s.baseURL))
	duration := time.Since(start)

	result := TestResult{
		Category:    "Basic",
		TestName:    "Health Check",
		Duration:    duration,
		Description: "Server health status",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data

		if s.verbose {
			result.Description = fmt.Sprintf("Status: %v", data["status"])
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testAPIRoot는 API 루트 테스트
func (s *TestSuite) testAPIRoot() {
	start := time.Now()
	resp, err := s.client.Get(fmt.Sprintf("%s/", s.baseURL))
	duration := time.Since(start)

	result := TestResult{
		Category:    "Basic",
		TestName:    "API Root",
		Duration:    duration,
		Description: "API endpoint information",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testServerInfo는 서버 정보 테스트
func (s *TestSuite) testServerInfo() {
	start := time.Now()
	resp, err := s.client.Get(fmt.Sprintf("%s/api/v1/server/info", s.baseURL))
	duration := time.Since(start)

	result := TestResult{
		Category:    "Basic",
		TestName:    "Server Info",
		Duration:    duration,
		Description: "Server capabilities and features",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data

		if s.verbose && data["vendor"] != nil {
			result.Description = fmt.Sprintf("Vendor: %v", data["vendor"])
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testSupportedVersions는 지원 버전 테스트
func (s *TestSuite) testSupportedVersions() {
	start := time.Now()
	resp, err := s.client.Get(fmt.Sprintf("%s/api/v1/server/versions", s.baseURL))
	duration := time.Since(start)

	result := TestResult{
		Category:    "Basic",
		TestName:    "Supported Versions",
		Duration:    duration,
		Description: "KMIP protocol versions",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data

		if s.verbose && data["supported_versions"] != nil {
			versions := data["supported_versions"].([]interface{})
			result.Description = fmt.Sprintf("Versions: %v", len(versions))
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testCreateSymmetricKey는 대칭 키 생성 테스트
func (s *TestSuite) testCreateSymmetricKey(algorithm string, length int) string {
	start := time.Now()
	testName := fmt.Sprintf("Create %s-%d", algorithm, length)

	reqBody := map[string]interface{}{
		"key_type":  "symmetric",
		"algorithm": algorithm,
		"length":    length,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keys", s.baseURL),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Symmetric",
		TestName:    testName,
		Duration:    duration,
		Description: fmt.Sprintf("Create %s-%d symmetric key", algorithm, length),
	}

	var keyID string

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 201
		result.Response = data

		if result.Success && data["key_id"] != nil {
			keyID = data["key_id"].(string)
			if s.verbose {
				result.Description = fmt.Sprintf("Key ID: %s", keyID)
			}
		} else if !result.Success {
			if data["error"] != nil {
				result.Error = data["error"].(string)
			}
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
	return keyID
}

// testCreateKeyPair는 키 쌍 생성 테스트
func (s *TestSuite) testCreateKeyPair(algorithm string, length int) {
	start := time.Now()
	testName := fmt.Sprintf("CreateKeyPair %s-%d", algorithm, length)

	reqBody := map[string]interface{}{
		"algorithm": algorithm,
		"length":    length,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keypairs", s.baseURL),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Asymmetric",
		TestName:    testName,
		Duration:    duration,
		Description: fmt.Sprintf("Create %s-%d key pair", algorithm, length),
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 201
		result.Response = data

		if result.Success && s.verbose {
			if data["public_key_id"] != nil {
				result.Description = fmt.Sprintf("Public: %s", data["public_key_id"])
			}
		} else if !result.Success {
			if data["error"] != nil {
				result.Error = data["error"].(string)
			}
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testGetKey는 키 조회 테스트
func (s *TestSuite) testGetKey(keyID string) {
	start := time.Now()
	resp, err := s.client.Get(fmt.Sprintf("%s/api/v1/keys/%s", s.baseURL, keyID))
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    "Get Key",
		Duration:    duration,
		Description: fmt.Sprintf("Retrieve key %s", keyID[:8]+"..."),
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testListKeys는 키 목록 조회 테스트
func (s *TestSuite) testListKeys() {
	start := time.Now()
	resp, err := s.client.Get(fmt.Sprintf("%s/api/v1/keys", s.baseURL))
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    "List Keys",
		Duration:    duration,
		Description: "List all keys",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data

		if s.verbose && data["total"] != nil {
			result.Description = fmt.Sprintf("Total keys: %.0f", data["total"].(float64))
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testDeleteKey는 키 삭제 테스트
func (s *TestSuite) testDeleteKey(keyID string) {
	start := time.Now()
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/keys/%s", s.baseURL, keyID), nil)
	resp, err := s.client.Do(req)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    "Delete Key",
		Duration:    duration,
		Description: fmt.Sprintf("Delete key %s", keyID[:8]+"..."),
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testRegisterKey는 키 등록 테스트
func (s *TestSuite) testRegisterKey() {
	start := time.Now()
	testName := "Register External Key"

	// 16바이트(128비트) 키 생성
	keyMaterial := "0123456789abcdef0123456789abcdef"

	reqBody := map[string]interface{}{
		"key_type":     "symmetric",
		"key_material": keyMaterial,
		"algorithm":    "AES",
		"length":       128,
		"attributes": map[string]interface{}{
			"name":   "registered-key",
			"source": "external-system",
		},
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keys/register", s.baseURL),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    testName,
		Duration:    duration,
		Description: "Register external key",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 201
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testLocateByAlternateName는 AlternateName으로 검색 테스트
func (s *TestSuite) testLocateByAlternateName(alternateName string) {
	start := time.Now()
	testName := "Locate by AlternateName"

	reqBody := map[string]interface{}{
		"alternate_name": alternateName,
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keys/search", s.baseURL),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    testName,
		Duration:    duration,
		Description: fmt.Sprintf("Search by alternate name: %s", alternateName),
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data

		if s.verbose && data["total"] != nil {
			result.Description = fmt.Sprintf("Found %.0f keys", data["total"].(float64))
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testGetAttributes는 속성 조회 테스트
func (s *TestSuite) testGetAttributes(keyID string) {
	start := time.Now()
	resp, err := s.client.Get(fmt.Sprintf("%s/api/v1/keys/attributes/%s", s.baseURL, keyID))
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    "Get Attributes",
		Duration:    duration,
		Description: fmt.Sprintf("Get attributes for %s", keyID[:8]+"..."),
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testAddAttributes는 속성 추가 테스트
func (s *TestSuite) testAddAttributes(keyID string) {
	start := time.Now()
	testName := "Add Attributes"

	reqBody := map[string]interface{}{
		"action": "add",
		"attributes": map[string]interface{}{
			"department":  "engineering",
			"cost_center": "CC-1234",
		},
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keys/attributes/%s", s.baseURL, keyID),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    testName,
		Duration:    duration,
		Description: "Add custom attributes",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testModifyAttributes는 속성 수정 테스트
func (s *TestSuite) testModifyAttributes(keyID string) {
	start := time.Now()
	testName := "Modify Attributes"

	reqBody := map[string]interface{}{
		"action": "modify",
		"attributes": map[string]interface{}{
			"status": "active",
		},
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keys/attributes/%s", s.baseURL, keyID),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    testName,
		Duration:    duration,
		Description: "Modify existing attributes",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testDeleteAttribute는 속성 삭제 테스트
func (s *TestSuite) testDeleteAttribute(keyID string) {
	start := time.Now()
	testName := "Delete Attribute"

	reqBody := map[string]interface{}{
		"attribute_name": "cost_center",
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(
		"DELETE",
		fmt.Sprintf("%s/api/v1/keys/attributes/%s", s.baseURL, keyID),
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    testName,
		Duration:    duration,
		Description: "Delete specific attribute",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testAddAlternateName는 AlternateName 추가 테스트
func (s *TestSuite) testAddAlternateName(keyID string, alternateName string) {
	start := time.Now()
	testName := "Add AlternateName"

	reqBody := map[string]interface{}{
		"action": "add",
		"attributes": map[string]interface{}{
			"AlternateName": []string{alternateName},
		},
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keys/attributes/%s", s.baseURL, keyID),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    testName,
		Duration:    duration,
		Description: fmt.Sprintf("Add alternate name: %s", alternateName),
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 200
		result.Response = data
		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// testRekey는 키 재생성 테스트
func (s *TestSuite) testRekey(keyID string) {
	start := time.Now()
	testName := "Rekey"

	reqBody := map[string]interface{}{
		"attributes": map[string]interface{}{
			"rotation_reason": "test-rotation",
		},
	}

	body, _ := json.Marshal(reqBody)
	resp, err := s.client.Post(
		fmt.Sprintf("%s/api/v1/keys/rekey/%s", s.baseURL, keyID),
		"application/json",
		bytes.NewReader(body),
	)
	duration := time.Since(start)

	result := TestResult{
		Category:    "Management",
		TestName:    testName,
		Duration:    duration,
		Description: "Regenerate key",
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		s.printTestResult(result, false)
	} else {
		defer resp.Body.Close()
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)

		result.Success = resp.StatusCode == 201
		result.Response = data

		if s.verbose && data["new_key_id"] != nil {
			result.Description = fmt.Sprintf("New key: %s", data["new_key_id"].(string)[:8]+"...")
		}

		s.printTestResult(result, result.Success)
	}

	s.results = append(s.results, result)
}

// printTestResult는 테스트 결과를 출력
func (s *TestSuite) printTestResult(result TestResult, success bool) {
	if success {
		fmt.Printf("  %s✓%s %-40s %s(%.2fms)%s",
			colorGreen, colorReset,
			result.TestName,
			colorCyan, result.Duration.Seconds()*1000, colorReset)
	} else {
		fmt.Printf("  %s✗%s %-40s %s(%.2fms)%s",
			colorRed, colorReset,
			result.TestName,
			colorCyan, result.Duration.Seconds()*1000, colorReset)
	}

	if s.verbose && result.Description != "" {
		fmt.Printf(" - %s", result.Description)
	}

	fmt.Println()

	if !success && result.Error != "" && s.verbose {
		fmt.Printf("    %sError: %s%s\n", colorYellow, result.Error, colorReset)
	}
}

// printSummary는 테스트 요약을 출력
func (s *TestSuite) printSummary() {
	fmt.Printf("\n%s========================================%s\n", colorBlue, colorReset)
	fmt.Printf("%sTest Summary%s\n", colorBlue, colorReset)
	fmt.Printf("%s========================================%s\n\n", colorBlue, colorReset)

	total := len(s.results)
	passed := 0
	failed := 0
	totalDuration := time.Duration(0)

	categoryStats := make(map[string]struct{ passed, failed int })

	for _, result := range s.results {
		totalDuration += result.Duration
		if result.Success {
			passed++
		} else {
			failed++
		}

		stats := categoryStats[result.Category]
		if result.Success {
			stats.passed++
		} else {
			stats.failed++
		}
		categoryStats[result.Category] = stats
	}

	successRate := float64(passed) / float64(total) * 100

	fmt.Printf("Total Tests:    %d\n", total)
	fmt.Printf("Passed:         %s%d (%.1f%%)%s\n", colorGreen, passed, successRate, colorReset)
	fmt.Printf("Failed:         %s%d (%.1f%%)%s\n", colorRed, failed, 100-successRate, colorReset)
	fmt.Printf("Total Duration: %.2fs\n", totalDuration.Seconds())
	fmt.Println()

	fmt.Println("Results by Category:")
	for category, stats := range categoryStats {
		total := stats.passed + stats.failed
		rate := float64(stats.passed) / float64(total) * 100
		fmt.Printf("  %-15s: %d/%d passed (%.1f%%)\n", category, stats.passed, total, rate)
	}
	fmt.Println()

	if failed > 0 {
		fmt.Printf("%sFailed Tests:%s\n", colorRed, colorReset)
		for _, result := range s.results {
			if !result.Success {
				fmt.Printf("  ✗ [%s] %s: %s\n", result.Category, result.TestName, result.Error)
			}
		}
		fmt.Println()
	}
}

// saveResults는 결과를 파일로 저장
func (s *TestSuite) saveResults(filename string) {
	output := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"summary": map[string]interface{}{
			"total":  len(s.results),
			"passed": s.countPassed(),
			"failed": s.countFailed(),
		},
		"results": s.results,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Printf("%sError saving results: %v%s\n", colorRed, err, colorReset)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("%sError writing file: %v%s\n", colorRed, err, colorReset)
		return
	}

	fmt.Printf("%sResults saved to: %s%s\n", colorGreen, filename, colorReset)
}

func (s *TestSuite) countPassed() int {
	count := 0
	for _, r := range s.results {
		if r.Success {
			count++
		}
	}
	return count
}

func (s *TestSuite) countFailed() int {
	return len(s.results) - s.countPassed()
}
