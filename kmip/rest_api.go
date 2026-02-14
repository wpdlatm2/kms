package kmip

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RESTAPIServer는 KMIP REST API 서버
type RESTAPIServer struct {
	server *Server
	mu     sync.RWMutex
}

// NewRESTAPIServer는 새로운 REST API 서버를 생성
func NewRESTAPIServer(server *Server) *RESTAPIServer {
	return &RESTAPIServer{
		server: server,
	}
}

// ServeHTTP는 REST API 서버를 시작
func (api *RESTAPIServer) ServeHTTP(addr string) error {
	mux := http.NewServeMux()

	// Swagger/OpenAPI 문서
	api.SetupSwaggerRoutes(mux)

	// KMIP 작업 엔드포인트
	mux.HandleFunc("/api/v1/keys", api.handleKeys)
	mux.HandleFunc("/api/v1/keys/", api.handleKeyByID)
	mux.HandleFunc("/api/v1/keypairs", api.handleKeyPairs)
	mux.HandleFunc("/api/v1/keys/register", api.handleRegisterKey)
	mux.HandleFunc("/api/v1/keys/search", api.handleSearchKeys)
	mux.HandleFunc("/api/v1/keys/attributes/", api.handleKeyAttributes)
	mux.HandleFunc("/api/v1/keys/rekey/", api.handleRekeyKey)
	mux.HandleFunc("/api/v1/server/info", api.handleServerInfo)
	mux.HandleFunc("/api/v1/server/versions", api.handleVersions)
	
	// 헬스체크
	mux.HandleFunc("/health", api.handleHealth)
	mux.HandleFunc("/", api.handleRoot)

	return http.ListenAndServe(addr, corsMiddleware(loggingMiddleware(mux)))
}

// handleRoot는 API 루트 정보를 반환
func (api *RESTAPIServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	info := map[string]interface{}{
		"service": "KMIP REST API Server",
		"version": "1.0.0",
		"documentation": map[string]string{
			"swagger_ui": "/docs",
			"redoc":      "/redoc",
			"openapi_yaml": "/api/v1/swagger.yaml",
			"openapi_json": "/api/v1/swagger.json",
		},
		"endpoints": map[string]string{
			"POST   /api/v1/keys":                 "Create a new symmetric key",
			"POST   /api/v1/keypairs":             "Create a new key pair (RSA/ECDSA)",
			"POST   /api/v1/keys/register":        "Register an existing key",
			"POST   /api/v1/keys/search":          "Search keys by attributes (Locate)",
			"GET    /api/v1/keys":                 "List all keys",
			"GET    /api/v1/keys/{id}":            "Get a key by ID",
			"DELETE /api/v1/keys/{id}":            "Delete a key by ID",
			"GET    /api/v1/keys/attributes/{id}": "Get key attributes",
			"POST   /api/v1/keys/attributes/{id}": "Add/Modify key attributes",
			"DELETE /api/v1/keys/attributes/{id}": "Delete key attribute",
			"POST   /api/v1/keys/rekey/{id}":      "Rekey (regenerate) a key",
			"GET    /api/v1/server/info":          "Get server information",
			"GET    /api/v1/server/versions":      "Get supported KMIP versions",
			"GET    /health":                      "Health check",
		},
		"timestamp": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// handleHealth는 헬스체크 엔드포인트
func (api *RESTAPIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleKeys는 키 목록 조회 및 생성
func (api *RESTAPIServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.handleListKeys(w, r)
	case http.MethodPost:
		api.handleCreateKey(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleKeyPairs는 키 쌍 생성 (RSA, ECDSA)
func (api *RESTAPIServer) handleKeyPairs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	api.handleCreateKeyPair(w, r)
}

// handleKeyByID는 개별 키 조회 및 삭제
func (api *RESTAPIServer) handleKeyByID(w http.ResponseWriter, r *http.Request) {
	// URL에서 ID 추출 (/api/v1/keys/{id})
	id := r.URL.Path[len("/api/v1/keys/"):]
	if id == "" {
		http.Error(w, "Key ID is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		api.handleGetKey(w, r, id)
	case http.MethodDelete:
		api.handleDeleteKey(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// CreateKeyRequest는 키 생성 요청
type CreateKeyRequest struct {
	KeyType            string                 `json:"key_type"`             // "symmetric", "public", "private"
	Algorithm          string                 `json:"algorithm,omitempty"`  // "AES", "RSA", etc.
	Length             int32                  `json:"length,omitempty"`     // Key length in bits
	Name               string                 `json:"name,omitempty"`       // Optional key name
	UsageMask          []string               `json:"usage_mask,omitempty"` // ["encrypt", "decrypt", "sign", etc.]
	Attributes         map[string]interface{} `json:"attributes,omitempty"` // Additional attributes
}

// CreateKeyResponse는 키 생성 응답
type CreateKeyResponse struct {
	KeyID      string                 `json:"key_id"`
	KeyType    string                 `json:"key_type"`
	Status     string                 `json:"status"`
	CreatedAt  time.Time              `json:"created_at"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// GetKeyResponse는 키 조회 응답
type GetKeyResponse struct {
	KeyID         string                 `json:"key_id"`
	KeyType       string                 `json:"key_type"`
	Algorithm     string                 `json:"algorithm,omitempty"`
	Length        int32                  `json:"length,omitempty"`
	KeyMaterial   string                 `json:"key_material,omitempty"` // Base64 encoded
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
	CreatedAt     time.Time              `json:"created_at,omitempty"`
}

// ListKeysResponse는 키 목록 응답
type ListKeysResponse struct {
	Keys  []KeySummary `json:"keys"`
	Total int          `json:"total"`
}

// KeySummary는 키 요약 정보
type KeySummary struct {
	KeyID      string    `json:"key_id"`
	KeyType    string    `json:"key_type"`
	Algorithm  string    `json:"algorithm,omitempty"`
	Length     int32     `json:"length,omitempty"`
	Name       string    `json:"name,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
}

// DeleteKeyResponse는 키 삭제 응답
type DeleteKeyResponse struct {
	KeyID     string    `json:"key_id"`
	Status    string    `json:"status"`
	DeletedAt time.Time `json:"deleted_at"`
}

// ServerInfoResponse는 서버 정보 응답
type ServerInfoResponse struct {
	Vendor            string   `json:"vendor"`
	ServerInfo        string   `json:"server_info"`
	SupportedVersions []string `json:"supported_versions"`
	Operations        []string `json:"operations"`
	ObjectTypes       []string `json:"object_types"`
}

// handleCreateKey는 새로운 키 생성
func (api *RESTAPIServer) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// 기본값 설정
	if req.KeyType == "" {
		req.KeyType = "symmetric"
	}
	if req.Algorithm == "" && req.KeyType == "symmetric" {
		req.Algorithm = "AES"
	}
	if req.Length == 0 {
		if req.KeyType == "symmetric" {
			req.Length = 256
		} else {
			req.Length = 2048 // RSA 기본값
		}
	}

	// Attributes 초기화
	if req.Attributes == nil {
		req.Attributes = make(map[string]interface{})
	}
	
	// 알고리즘과 길이를 속성에 추가
	algorithm := GetAlgorithmFromString(req.Algorithm)
	req.Attributes["CryptographicAlgorithm"] = algorithm
	req.Attributes["CryptographicLength"] = req.Length

	// KMIP Create 요청 생성
	batchItem := BatchRequestItem{
		Operation: OperationCreate,
		RequestPayload: &CreateRequest{
			ObjectType: getObjectTypeFromString(req.KeyType),
			Attributes: req.Attributes,
		},
	}

	// 요청 처리
	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Key creation failed"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	// 응답 생성
	response := CreateKeyResponse{
		KeyID:      *respItem.UniqueIdentifier,
		KeyType:    req.KeyType,
		Status:     "created",
		CreatedAt:  time.Now().UTC(),
		Attributes: req.Attributes,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleCreateKeyPair는 키 쌍 생성 (RSA, ECDSA)
func (api *RESTAPIServer) handleCreateKeyPair(w http.ResponseWriter, r *http.Request) {
	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// 기본값 설정
	if req.Algorithm == "" {
		req.Algorithm = "RSA"
	}
	if req.Length == 0 {
		if req.Algorithm == "RSA" {
			req.Length = 2048
		} else if req.Algorithm == "ECDSA" {
			req.Length = 256
		}
	}

	// Attributes 초기화
	if req.Attributes == nil {
		req.Attributes = make(map[string]interface{})
	}
	
	// 알고리즘과 길이를 속성에 추가
	algorithm := GetAlgorithmFromString(req.Algorithm)
	req.Attributes["CryptographicAlgorithm"] = algorithm
	req.Attributes["CryptographicLength"] = req.Length

	// KMIP CreateKeyPair 요청 생성
	batchItem := BatchRequestItem{
		Operation: OperationCreateKeyPair,
		RequestPayload: &CreateRequest{
			Attributes: req.Attributes,
		},
	}

	// 요청 처리
	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Key pair creation failed"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	// 키 쌍 ID 추출
	keyPairIDs := map[string]string{
		"public_key_id":  "",
		"private_key_id": "",
	}
	
	if payload, ok := respItem.ResponsePayload.(map[string]string); ok {
		keyPairIDs = payload
	}

	// 응답 생성
	response := map[string]interface{}{
		"public_key_id":  keyPairIDs["public_key_id"],
		"private_key_id": keyPairIDs["private_key_id"],
		"algorithm":      req.Algorithm,
		"length":         req.Length,
		"status":         "created",
		"created_at":     time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleGetKey는 키 조회
func (api *RESTAPIServer) handleGetKey(w http.ResponseWriter, r *http.Request, keyID string) {
	// KMIP Get 요청 생성
	batchItem := BatchRequestItem{
		Operation:        OperationGet,
		UniqueIdentifier: &keyID,
		RequestPayload: &GetRequest{
			UniqueIdentifier: &keyID,
		},
	}

	// 요청 처리
	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		if respItem.ResultMessage != nil && *respItem.ResultMessage == "object not found" {
			respondError(w, http.StatusNotFound, "Key not found", nil)
		} else {
			msg := "Failed to retrieve key"
			if respItem.ResultMessage != nil {
				msg = *respItem.ResultMessage
			}
			respondError(w, http.StatusInternalServerError, msg, nil)
		}
		return
	}

	// ManagedObject를 응답으로 변환
	var response GetKeyResponse
	if obj, ok := respItem.ResponsePayload.(ManagedObject); ok {
		response.KeyID = obj.GetUniqueIdentifier()
		response.KeyType = getStringFromObjectType(obj.GetObjectType())
		response.Attributes = obj.GetAttributes()
		response.CreatedAt = time.Now().UTC() // 실제로는 객체에서 가져와야 함

		// 타입별로 추가 정보 처리
		switch v := obj.(type) {
		case *SymmetricKey:
			if v.KeyBlock.CryptographicAlgorithm != nil {
				response.Algorithm = GetAlgorithmString(*v.KeyBlock.CryptographicAlgorithm)
			}
			if v.KeyBlock.CryptographicLength != nil {
				response.Length = *v.KeyBlock.CryptographicLength
			}
			// Base64 인코딩된 키 자료 (보안상 주의!)
			if len(v.KeyBlock.KeyValue.KeyMaterial) > 0 {
				response.KeyMaterial = fmt.Sprintf("%x", v.KeyBlock.KeyValue.KeyMaterial)
			}
			
		case *PublicKey:
			if v.KeyBlock.CryptographicAlgorithm != nil {
				response.Algorithm = GetAlgorithmString(*v.KeyBlock.CryptographicAlgorithm)
			}
			if v.KeyBlock.CryptographicLength != nil {
				response.Length = *v.KeyBlock.CryptographicLength
			}
			// 공개 키는 PEM 형식으로 반환 가능
			if len(v.KeyBlock.KeyValue.KeyMaterial) > 0 {
				response.KeyMaterial = fmt.Sprintf("%x", v.KeyBlock.KeyValue.KeyMaterial)
			}
			
		case *PrivateKey:
			if v.KeyBlock.CryptographicAlgorithm != nil {
				response.Algorithm = GetAlgorithmString(*v.KeyBlock.CryptographicAlgorithm)
			}
			if v.KeyBlock.CryptographicLength != nil {
				response.Length = *v.KeyBlock.CryptographicLength
			}
			// 개인 키 자료는 매우 민감하므로 주의!
			// 프로덕션에서는 권한 체크 필수
			if len(v.KeyBlock.KeyValue.KeyMaterial) > 0 {
				response.KeyMaterial = fmt.Sprintf("%x", v.KeyBlock.KeyValue.KeyMaterial)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleListKeys는 키 목록 조회
func (api *RESTAPIServer) handleListKeys(w http.ResponseWriter, r *http.Request) {
	// 저장소에서 모든 객체 조회
	objects := api.server.store.List()

	keys := make([]KeySummary, 0, len(objects))
	for _, obj := range objects {
		summary := KeySummary{
			KeyID:   obj.GetUniqueIdentifier(),
			KeyType: getStringFromObjectType(obj.GetObjectType()),
		}

		// 타입별로 추가 정보 처리
		switch v := obj.(type) {
		case *SymmetricKey:
			if v.KeyBlock.CryptographicAlgorithm != nil {
				summary.Algorithm = GetAlgorithmString(*v.KeyBlock.CryptographicAlgorithm)
			}
			if v.KeyBlock.CryptographicLength != nil {
				summary.Length = *v.KeyBlock.CryptographicLength
			}
			
		case *PublicKey:
			if v.KeyBlock.CryptographicAlgorithm != nil {
				summary.Algorithm = GetAlgorithmString(*v.KeyBlock.CryptographicAlgorithm)
			}
			if v.KeyBlock.CryptographicLength != nil {
				summary.Length = *v.KeyBlock.CryptographicLength
			}
			
		case *PrivateKey:
			if v.KeyBlock.CryptographicAlgorithm != nil {
				summary.Algorithm = GetAlgorithmString(*v.KeyBlock.CryptographicAlgorithm)
			}
			if v.KeyBlock.CryptographicLength != nil {
				summary.Length = *v.KeyBlock.CryptographicLength
			}
		}

		keys = append(keys, summary)
	}

	response := ListKeysResponse{
		Keys:  keys,
		Total: len(keys),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDeleteKey는 키 삭제
func (api *RESTAPIServer) handleDeleteKey(w http.ResponseWriter, r *http.Request, keyID string) {
	// KMIP Destroy 요청 생성
	batchItem := BatchRequestItem{
		Operation:        OperationDestroy,
		UniqueIdentifier: &keyID,
		RequestPayload: &DestroyRequest{
			UniqueIdentifier: &keyID,
		},
	}

	// 요청 처리
	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		if respItem.ResultMessage != nil && *respItem.ResultMessage == "object not found" {
			respondError(w, http.StatusNotFound, "Key not found", nil)
		} else {
			msg := "Failed to delete key"
			if respItem.ResultMessage != nil {
				msg = *respItem.ResultMessage
			}
			respondError(w, http.StatusInternalServerError, msg, nil)
		}
		return
	}

	response := DeleteKeyResponse{
		KeyID:     keyID,
		Status:    "deleted",
		DeletedAt: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleServerInfo는 서버 정보 조회
func (api *RESTAPIServer) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// KMIP Query 요청 생성
	batchItem := BatchRequestItem{
		Operation: OperationQuery,
	}

	// 요청 처리
	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		respondError(w, http.StatusInternalServerError, "Failed to query server", nil)
		return
	}

	// QueryResponse 변환
	var response ServerInfoResponse
	if queryResp, ok := respItem.ResponsePayload.(*QueryResponse); ok {
		if queryResp.VendorIdentification != nil {
			response.Vendor = *queryResp.VendorIdentification
		}
		if queryResp.ServerInformation != nil {
			response.ServerInfo = *queryResp.ServerInformation
		}

		// 버전 목록
		response.SupportedVersions = make([]string, len(queryResp.ProtocolVersions))
		for i, v := range queryResp.ProtocolVersions {
			response.SupportedVersions[i] = fmt.Sprintf("%d.%d", v.Major, v.Minor)
		}

		// 작업 목록
		response.Operations = make([]string, len(queryResp.Operations))
		for i, op := range queryResp.Operations {
			response.Operations[i] = getOperationString(op)
		}

		// 객체 타입 목록
		response.ObjectTypes = make([]string, len(queryResp.ObjectTypes))
		for i, ot := range queryResp.ObjectTypes {
			response.ObjectTypes[i] = getStringFromObjectType(ot)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleVersions는 지원 버전 조회
func (api *RESTAPIServer) handleVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// KMIP DiscoverVersions 요청 생성
	batchItem := BatchRequestItem{
		Operation: OperationDiscoverVersions,
	}

	// 요청 처리
	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		respondError(w, http.StatusInternalServerError, "Failed to discover versions", nil)
		return
	}

	// DiscoverVersionsResponse 변환
	var versions []string
	if discoverResp, ok := respItem.ResponsePayload.(*DiscoverVersionsResponse); ok {
		versions = make([]string, len(discoverResp.ProtocolVersions))
		for i, v := range discoverResp.ProtocolVersions {
			versions[i] = fmt.Sprintf("%d.%d", v.Major, v.Minor)
		}
	}

	response := map[string]interface{}{
		"supported_versions": versions,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRegisterKey는 외부 키 등록
func (api *RESTAPIServer) handleRegisterKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		KeyType     string `json:"key_type"`
		KeyMaterial string `json:"key_material"` // hex-encoded
		Algorithm   string `json:"algorithm,omitempty"`
		Length      int32  `json:"length,omitempty"`
		Attributes  map[string]interface{} `json:"attributes,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// hex 디코딩
	keyMaterialBytes, err := hex.DecodeString(req.KeyMaterial)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid key material (must be hex)", err)
		return
	}

	// ManagedObject 생성
	var managedObj ManagedObject
	algorithm := GetAlgorithmFromString(req.Algorithm)

	switch req.KeyType {
	case "symmetric":
		managedObj = &SymmetricKey{
			KeyBlock: KeyBlock{
				KeyFormatType: 0x00000001, // Raw
				KeyValue: KeyValue{
					KeyMaterial: keyMaterialBytes,
					Attributes:  make(map[string]interface{}),
				},
				CryptographicAlgorithm: &algorithm,
				CryptographicLength:    &req.Length,
			},
			Attributes: req.Attributes,
		}
	case "public":
		managedObj = &PublicKey{
			KeyBlock: KeyBlock{
				KeyFormatType: 0x00000002, // PKIX
				KeyValue: KeyValue{
					KeyMaterial: keyMaterialBytes,
					Attributes:  make(map[string]interface{}),
				},
				CryptographicAlgorithm: &algorithm,
				CryptographicLength:    &req.Length,
			},
			Attributes: req.Attributes,
		}
	case "private":
		managedObj = &PrivateKey{
			KeyBlock: KeyBlock{
				KeyFormatType: 0x00000002, // PKCS#8
				KeyValue: KeyValue{
					KeyMaterial: keyMaterialBytes,
					Attributes:  make(map[string]interface{}),
				},
				CryptographicAlgorithm: &algorithm,
				CryptographicLength:    &req.Length,
			},
			Attributes: req.Attributes,
		}
	default:
		respondError(w, http.StatusBadRequest, "Invalid key type", nil)
		return
	}

	// KMIP Register 요청
	batchItem := BatchRequestItem{
		Operation: OperationRegister,
		RequestPayload: &RegisterRequest{
			ObjectType:    getObjectTypeFromString(req.KeyType),
			ManagedObject: managedObj,
			Attributes:    req.Attributes,
		},
	}

	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Key registration failed"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	response := map[string]interface{}{
		"key_id":     *respItem.UniqueIdentifier,
		"key_type":   req.KeyType,
		"status":     "registered",
		"created_at": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleSearchKeys는 키 검색 (Locate)
func (api *RESTAPIServer) handleSearchKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Attributes    map[string]interface{} `json:"attributes,omitempty"`
		AlternateName string                 `json:"alternate_name,omitempty"`
		MaxResults    *int32                 `json:"max_results,omitempty"`
		OffsetItems   *int32                 `json:"offset,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// AlternateName이 제공되면 속성에 추가
	if req.AlternateName != "" {
		if req.Attributes == nil {
			req.Attributes = make(map[string]interface{})
		}
		req.Attributes["AlternateName"] = req.AlternateName
	}

	// KMIP Locate 요청
	batchItem := BatchRequestItem{
		Operation: OperationLocate,
		RequestPayload: &LocateRequest{
			Attributes:   req.Attributes,
			MaximumItems: req.MaxResults,
			OffsetItems:  req.OffsetItems,
		},
	}

	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Search failed"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	var keyIDs []string
	if locateResp, ok := respItem.ResponsePayload.(*LocateResponse); ok {
		keyIDs = locateResp.UniqueIdentifiers
	}

	response := map[string]interface{}{
		"key_ids": keyIDs,
		"total":   len(keyIDs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleKeyAttributes는 키 속성 관리
func (api *RESTAPIServer) handleKeyAttributes(w http.ResponseWriter, r *http.Request) {
	// URL에서 ID 추출
	path := r.URL.Path
	prefix := "/api/v1/keys/attributes/"
	if !strings.HasPrefix(path, prefix) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	keyID := path[len(prefix):]

	switch r.Method {
	case http.MethodGet:
		api.handleGetAttributes(w, r, keyID)
	case http.MethodPost:
		api.handleAddOrModifyAttributes(w, r, keyID)
	case http.MethodDelete:
		api.handleDeleteAttributes(w, r, keyID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetAttributes는 키 속성 조회
func (api *RESTAPIServer) handleGetAttributes(w http.ResponseWriter, r *http.Request, keyID string) {
	batchItem := BatchRequestItem{
		Operation: OperationGetAttributes,
		RequestPayload: &GetAttributesRequest{
			UniqueIdentifier: &keyID,
			AttributeNames:   []string{}, // 모든 속성
		},
	}

	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Failed to get attributes"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	var attributes map[string]interface{}
	if getAttrResp, ok := respItem.ResponsePayload.(*GetAttributesResponse); ok {
		attributes = getAttrResp.Attributes
	}

	response := map[string]interface{}{
		"key_id":     keyID,
		"attributes": attributes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAddOrModifyAttributes는 속성 추가/수정
func (api *RESTAPIServer) handleAddOrModifyAttributes(w http.ResponseWriter, r *http.Request, keyID string) {
	var req struct {
		Attributes map[string]interface{} `json:"attributes"`
		Action     string                 `json:"action"` // "add" or "modify"
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	operation := OperationAddAttribute
	if req.Action == "modify" {
		operation = OperationModifyAttribute
	}

	var requestPayload interface{}
	if operation == OperationAddAttribute {
		requestPayload = &AddAttributeRequest{
			UniqueIdentifier: &keyID,
			Attribute:        req.Attributes,
		}
	} else {
		requestPayload = &ModifyAttributeRequest{
			UniqueIdentifier: &keyID,
			Attribute:        req.Attributes,
		}
	}

	batchItem := BatchRequestItem{
		Operation:      operation,
		RequestPayload: requestPayload,
	}

	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Failed to update attributes"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	response := map[string]interface{}{
		"key_id": keyID,
		"status": "updated",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDeleteAttributes는 속성 삭제
func (api *RESTAPIServer) handleDeleteAttributes(w http.ResponseWriter, r *http.Request, keyID string) {
	var req struct {
		AttributeName string `json:"attribute_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	batchItem := BatchRequestItem{
		Operation: OperationDeleteAttribute,
		RequestPayload: &DeleteAttributeRequest{
			UniqueIdentifier: &keyID,
			AttributeName:    req.AttributeName,
		},
	}

	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Failed to delete attribute"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	response := map[string]interface{}{
		"key_id": keyID,
		"status": "deleted",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRekeyKey는 키 재생성
func (api *RESTAPIServer) handleRekeyKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL에서 ID 추출
	path := r.URL.Path
	prefix := "/api/v1/keys/rekey/"
	if !strings.HasPrefix(path, prefix) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	keyID := path[len(prefix):]

	var req struct {
		Attributes map[string]interface{} `json:"attributes,omitempty"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	batchItem := BatchRequestItem{
		Operation: OperationRekey,
		RequestPayload: &RekeyRequest{
			UniqueIdentifier: &keyID,
			Attributes:       req.Attributes,
		},
	}

	respItem := api.server.handleOperation(&batchItem)

	if respItem.ResultStatus != ResultStatusSuccess {
		msg := "Rekey failed"
		if respItem.ResultMessage != nil {
			msg = *respItem.ResultMessage
		}
		respondError(w, http.StatusInternalServerError, msg, nil)
		return
	}

	var newKeyID string
	if rekeyResp, ok := respItem.ResponsePayload.(*RekeyResponse); ok {
		newKeyID = rekeyResp.UniqueIdentifier
	}

	response := map[string]interface{}{
		"old_key_id": keyID,
		"new_key_id": newKeyID,
		"status":     "rekeyed",
		"created_at": time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// 헬퍼 함수들

func respondError(w http.ResponseWriter, status int, message string, err error) {
	response := map[string]interface{}{
		"error":   message,
		"status":  status,
	}
	if err != nil {
		response["details"] = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func getObjectTypeFromString(s string) int32 {
	switch s {
	case "symmetric":
		return ObjectTypeSymmetricKey
	case "public":
		return ObjectTypePublicKey
	case "private":
		return ObjectTypePrivateKey
	case "certificate":
		return ObjectTypeCertificate
	default:
		return ObjectTypeSymmetricKey
	}
}

func getStringFromObjectType(ot int32) string {
	switch ot {
	case ObjectTypeSymmetricKey:
		return "symmetric"
	case ObjectTypePublicKey:
		return "public"
	case ObjectTypePrivateKey:
		return "private"
	case ObjectTypeCertificate:
		return "certificate"
	default:
		return "unknown"
	}
}

func getOperationString(op int32) string {
	switch op {
	case OperationCreate:
		return "Create"
	case OperationCreateKeyPair:
		return "CreateKeyPair"
	case OperationGet:
		return "Get"
	case OperationDestroy:
		return "Destroy"
	case OperationQuery:
		return "Query"
	case OperationDiscoverVersions:
		return "DiscoverVersions"
	default:
		return fmt.Sprintf("Unknown(%d)", op)
	}
}

// 미들웨어

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// 요청 처리
		next.ServeHTTP(w, r)
		
		// 로그 출력
		duration := time.Since(start)
		fmt.Printf("[%s] %s %s - %v\n", 
			time.Now().Format("2006-01-02 15:04:05"),
			r.Method, 
			r.URL.Path, 
			duration,
		)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}
