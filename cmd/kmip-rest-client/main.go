package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
)

func main() {
	// 커맨드 라인 플래그
	addr := flag.String("addr", "http://localhost:9090", "REST API server address")
	operation := flag.String("op", "", "Operation: create, createkeypair, get, list, delete, info, versions")
	keyID := flag.String("id", "", "Key ID (for get/delete operations)")
	keyType := flag.String("type", "symmetric", "Key type: symmetric, public, private")
	algorithm := flag.String("algo", "AES", "Algorithm: AES, RSA, ECDSA, etc.")
	length := flag.Int("length", 256, "Key length in bits")
	name := flag.String("name", "", "Key name (optional)")
	pretty := flag.Bool("pretty", true, "Pretty print JSON output")
	
	flag.Parse()

	if *operation == "" {
		fmt.Println("Usage: kmip-rest-client -op <operation> [options]")
		fmt.Println("\nOperations:")
		fmt.Println("  create       - Create a new symmetric key")
		fmt.Println("  createkeypair - Create a new key pair (RSA/ECDSA)")
		fmt.Println("  get          - Get a key by ID")
		fmt.Println("  list         - List all keys")
		fmt.Println("  delete       - Delete a key by ID")
		fmt.Println("  info         - Get server information")
		fmt.Println("  versions     - Get supported KMIP versions")
		fmt.Println("\nExamples:")
		fmt.Println("  # Symmetric key")
		fmt.Println("  kmip-rest-client -op create -type symmetric -algo AES -length 256")
		fmt.Println("")
		fmt.Println("  # RSA key pair")
		fmt.Println("  kmip-rest-client -op createkeypair -algo RSA -length 2048")
		fmt.Println("")
		fmt.Println("  # ECDSA key pair")
		fmt.Println("  kmip-rest-client -op createkeypair -algo ECDSA -length 256")
		fmt.Println("")
		fmt.Println("  # List keys")
		fmt.Println("  kmip-rest-client -op list")
		fmt.Println("")
		fmt.Println("  # Get key")
		fmt.Println("  kmip-rest-client -op get -id <key-id>")
		fmt.Println("")
		fmt.Println("  # Delete key")
		fmt.Println("  kmip-rest-client -op delete -id <key-id>")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 10 * time.Second}

	switch *operation {
	case "create":
		createKey(client, *addr, *keyType, *algorithm, *length, *name, *pretty)
	case "createkeypair":
		createKeyPair(client, *addr, *algorithm, *length, *pretty)
	case "get":
		if *keyID == "" {
			fmt.Println("Error: -id is required for get operation")
			os.Exit(1)
		}
		getKey(client, *addr, *keyID, *pretty)
	case "list":
		listKeys(client, *addr, *pretty)
	case "delete":
		if *keyID == "" {
			fmt.Println("Error: -id is required for delete operation")
			os.Exit(1)
		}
		deleteKey(client, *addr, *keyID, *pretty)
	case "info":
		serverInfo(client, *addr, *pretty)
	case "versions":
		versions(client, *addr, *pretty)
	default:
		fmt.Printf("Error: Unknown operation '%s'\n", *operation)
		os.Exit(1)
	}
}

// createKey는 새로운 키 생성
func createKey(client *http.Client, addr, keyType, algorithm string, length int, name string, pretty bool) {
	url := fmt.Sprintf("%s/api/v1/keys", addr)
	
	req := map[string]interface{}{
		"key_type":  keyType,
		"algorithm": algorithm,
		"length":    length,
	}
	if name != "" {
		req["name"] = name
	}

	body, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		printError(resp)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%sError parsing response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Key created successfully%s\n\n", colorGreen, colorReset)
	fmt.Printf("%sKey ID:%s %s\n", colorCyan, colorReset, result["key_id"])
	fmt.Printf("%sType:%s %s\n", colorCyan, colorReset, result["key_type"])
	fmt.Printf("%sStatus:%s %s\n", colorCyan, colorReset, result["status"])
	
	if pretty {
		fmt.Printf("\n%sFull Response:%s\n", colorYellow, colorReset)
		printJSON(result)
	}
}

// createKeyPair는 키 쌍 생성 (RSA, ECDSA)
func createKeyPair(client *http.Client, addr, algorithm string, length int, pretty bool) {
	url := fmt.Sprintf("%s/api/v1/keypairs", addr)
	
	req := map[string]interface{}{
		"algorithm": algorithm,
		"length":    length,
	}

	body, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		printError(resp)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%sError parsing response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Key pair created successfully%s\n\n", colorGreen, colorReset)
	fmt.Printf("%sPublic Key ID:%s %s\n", colorCyan, colorReset, result["public_key_id"])
	fmt.Printf("%sPrivate Key ID:%s %s\n", colorCyan, colorReset, result["private_key_id"])
	fmt.Printf("%sAlgorithm:%s %s\n", colorCyan, colorReset, result["algorithm"])
	fmt.Printf("%sLength:%s %.0f bits\n", colorCyan, colorReset, result["length"])
	fmt.Printf("%sStatus:%s %s\n", colorCyan, colorReset, result["status"])
	
	if pretty {
		fmt.Printf("\n%sFull Response:%s\n", colorYellow, colorReset)
		printJSON(result)
	}
}

// getKey는 키 조회
func getKey(client *http.Client, addr, keyID string, pretty bool) {
	url := fmt.Sprintf("%s/api/v1/keys/%s", addr, keyID)
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		printError(resp)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%sError parsing response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Key retrieved successfully%s\n\n", colorGreen, colorReset)
	fmt.Printf("%sKey ID:%s %s\n", colorCyan, colorReset, result["key_id"])
	fmt.Printf("%sType:%s %s\n", colorCyan, colorReset, result["key_type"])
	
	if algo, ok := result["algorithm"]; ok {
		fmt.Printf("%sAlgorithm:%s %s\n", colorCyan, colorReset, algo)
	}
	if length, ok := result["length"]; ok {
		fmt.Printf("%sLength:%s %.0f bits\n", colorCyan, colorReset, length)
	}
	if keyMat, ok := result["key_material"]; ok {
		fmt.Printf("%sKey Material:%s %s\n", colorCyan, colorReset, keyMat)
	}
	
	if pretty {
		fmt.Printf("\n%sFull Response:%s\n", colorYellow, colorReset)
		printJSON(result)
	}
}

// listKeys는 키 목록 조회
func listKeys(client *http.Client, addr string, pretty bool) {
	url := fmt.Sprintf("%s/api/v1/keys", addr)
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		printError(resp)
		os.Exit(1)
	}

	var result struct {
		Keys  []map[string]interface{} `json:"keys"`
		Total int                      `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%sError parsing response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Found %d key(s)%s\n\n", colorGreen, result.Total, colorReset)

	if result.Total == 0 {
		fmt.Println("No keys found.")
		return
	}

	// 테이블 형식으로 출력
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%sKEY ID\tTYPE\tALGORITHM\tLENGTH%s\n", colorBlue, colorReset)
	fmt.Fprintf(w, "%s%s\t%s\t%s\t%s%s\n", colorBlue, "------", "----", "---------", "------", colorReset)
	
	for _, key := range result.Keys {
		keyID := key["key_id"]
		keyType := key["key_type"]
		algo := "-"
		if a, ok := key["algorithm"]; ok {
			algo = fmt.Sprintf("%v", a)
		}
		length := "-"
		if l, ok := key["length"]; ok {
			length = fmt.Sprintf("%.0f", l)
		}
		
		fmt.Fprintf(w, "%v\t%v\t%s\t%s\n", keyID, keyType, algo, length)
	}
	w.Flush()

	if pretty {
		fmt.Printf("\n%sFull Response:%s\n", colorYellow, colorReset)
		printJSON(result)
	}
}

// deleteKey는 키 삭제
func deleteKey(client *http.Client, addr, keyID string, pretty bool) {
	url := fmt.Sprintf("%s/api/v1/keys/%s", addr, keyID)
	
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		printError(resp)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%sError parsing response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Key deleted successfully%s\n\n", colorGreen, colorReset)
	fmt.Printf("%sKey ID:%s %s\n", colorCyan, colorReset, result["key_id"])
	fmt.Printf("%sStatus:%s %s\n", colorCyan, colorReset, result["status"])
	
	if pretty {
		fmt.Printf("\n%sFull Response:%s\n", colorYellow, colorReset)
		printJSON(result)
	}
}

// serverInfo는 서버 정보 조회
func serverInfo(client *http.Client, addr string, pretty bool) {
	url := fmt.Sprintf("%s/api/v1/server/info", addr)
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		printError(resp)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%sError parsing response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Server Information%s\n\n", colorGreen, colorReset)
	
	if vendor, ok := result["vendor"]; ok {
		fmt.Printf("%sVendor:%s %s\n", colorCyan, colorReset, vendor)
	}
	if info, ok := result["server_info"]; ok {
		fmt.Printf("%sServer:%s %s\n", colorCyan, colorReset, info)
	}
	
	if versions, ok := result["supported_versions"].([]interface{}); ok {
		fmt.Printf("%sSupported Versions:%s\n", colorCyan, colorReset)
		for _, v := range versions {
			fmt.Printf("  - %s\n", v)
		}
	}
	
	if ops, ok := result["operations"].([]interface{}); ok {
		fmt.Printf("%sOperations:%s\n", colorCyan, colorReset)
		for _, op := range ops {
			fmt.Printf("  - %s\n", op)
		}
	}
	
	if types, ok := result["object_types"].([]interface{}); ok {
		fmt.Printf("%sObject Types:%s\n", colorCyan, colorReset)
		for _, t := range types {
			fmt.Printf("  - %s\n", t)
		}
	}
	
	if pretty {
		fmt.Printf("\n%sFull Response:%s\n", colorYellow, colorReset)
		printJSON(result)
	}
}

// versions는 지원 버전 조회
func versions(client *http.Client, addr string, pretty bool) {
	url := fmt.Sprintf("%s/api/v1/server/versions", addr)
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		printError(resp)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("%sError parsing response: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s✓ Supported KMIP Versions%s\n\n", colorGreen, colorReset)
	
	if versions, ok := result["supported_versions"].([]interface{}); ok {
		for _, v := range versions {
			fmt.Printf("  %s✓%s KMIP %s\n", colorGreen, colorReset, v)
		}
	}
	
	if pretty {
		fmt.Printf("\n%sFull Response:%s\n", colorYellow, colorReset)
		printJSON(result)
	}
}

// 헬퍼 함수들

func printError(resp *http.Response) {
	body, _ := io.ReadAll(resp.Body)
	
	var errResp map[string]interface{}
	if err := json.Unmarshal(body, &errResp); err == nil {
		fmt.Printf("%s✗ Error: %s%s\n", colorRed, errResp["error"], colorReset)
		if details, ok := errResp["details"]; ok {
			fmt.Printf("%sDetails: %s%s\n", colorYellow, details, colorReset)
		}
	} else {
		fmt.Printf("%s✗ Error: %s%s\n", colorRed, string(body), colorReset)
	}
	fmt.Printf("%sStatus Code: %d%s\n", colorYellow, resp.StatusCode, colorReset)
}

func printJSON(data interface{}) {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("Error formatting JSON: %v\n", err)
		return
	}
	fmt.Println(string(output))
}
