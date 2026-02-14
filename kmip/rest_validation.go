package kmip

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// validationMiddleware는 입력값 검증 미들웨어
func validationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validator := NewInputValidator()
		
		// JSON 크기 검증
		if r.ContentLength > 0 {
			if err := validator.ValidateJSONSize(r.ContentLength); err != nil {
				respondValidationError(w, err)
				return
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

// respondValidationError는 검증 오류 응답
func respondValidationError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	
	response := map[string]interface{}{
		"error":   "validation_error",
		"message": err.Error(),
	}
	
	json.NewEncoder(w).Encode(response)
}

// ValidatedCreateKeyRequest는 검증된 키 생성 요청
type ValidatedCreateKeyRequest struct {
	KeyType    string                 `json:"key_type"`
	Algorithm  string                 `json:"algorithm"`
	Length     int32                  `json:"length"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Validate는 키 생성 요청 검증
func (req *ValidatedCreateKeyRequest) Validate(validator *InputValidator) error {
	// 키 타입 검증
	if req.KeyType != "symmetric" && req.KeyType != "asymmetric" {
		return &ValidationError{"key_type", "key_type must be 'symmetric' or 'asymmetric'"}
	}
	
	// 알고리즘 검증
	if err := validator.ValidateAlgorithm(req.Algorithm); err != nil {
		return err
	}
	
	// 키 길이 검증
	if err := validator.ValidateKeyLength(req.Algorithm, req.Length); err != nil {
		return err
	}
	
	// 속성 검증
	if req.Attributes != nil {
		if err := validator.ValidateAttributes(req.Attributes); err != nil {
			return err
		}
	}
	
	return nil
}

// ValidatedRegisterKeyRequest는 검증된 키 등록 요청
type ValidatedRegisterKeyRequest struct {
	KeyType     string                 `json:"key_type"`
	KeyMaterial string                 `json:"key_material"`
	Algorithm   string                 `json:"algorithm"`
	Length      int32                  `json:"length"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
}

// Validate는 키 등록 요청 검증
func (req *ValidatedRegisterKeyRequest) Validate(validator *InputValidator) error {
	// 키 타입 검증
	validTypes := map[string]bool{
		"symmetric": true,
		"public":    true,
		"private":   true,
	}
	if !validTypes[req.KeyType] {
		return &ValidationError{"key_type", "invalid key_type"}
	}
	
	// 키 자료 검증
	if err := validator.ValidateKeyMaterial(req.KeyMaterial); err != nil {
		return err
	}
	
	// 알고리즘 검증
	if err := validator.ValidateAlgorithm(req.Algorithm); err != nil {
		return err
	}
	
	// 키 길이 검증
	if err := validator.ValidateKeyLength(req.Algorithm, req.Length); err != nil {
		return err
	}
	
	// 속성 검증
	if req.Attributes != nil {
		if err := validator.ValidateAttributes(req.Attributes); err != nil {
			return err
		}
	}
	
	// 키 자료 길이와 선언된 길이 일치 확인
	expectedBytes := req.Length / 8
	actualBytes := int32(len(req.KeyMaterial) / 2)
	if actualBytes != expectedBytes {
		return &ValidationError{"key_material", fmt.Sprintf("key material length mismatch: expected %d bytes, got %d bytes", expectedBytes, actualBytes)}
	}
	
	return nil
}

// ValidatedSearchRequest는 검증된 검색 요청
type ValidatedSearchRequest struct {
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
	AlternateName string                 `json:"alternate_name,omitempty"`
	MaxResults    *int32                 `json:"max_results,omitempty"`
	OffsetItems   *int32                 `json:"offset,omitempty"`
}

// Validate는 검색 요청 검증
func (req *ValidatedSearchRequest) Validate(validator *InputValidator) error {
	// 속성 검증
	if req.Attributes != nil {
		if err := validator.ValidateAttributes(req.Attributes); err != nil {
			return err
		}
	}
	
	// 대체 이름 검증
	if req.AlternateName != "" {
		req.AlternateName = validator.SanitizeString(req.AlternateName)
		if len(req.AlternateName) > MaxStringLength {
			return &ValidationError{"alternate_name", "alternate_name too long"}
		}
	}
	
	// 결과 제한 검증
	if err := validator.ValidateSearchLimit(req.MaxResults); err != nil {
		return err
	}
	
	// 오프셋 검증
	if err := validator.ValidateOffset(req.OffsetItems); err != nil {
		return err
	}
	
	return nil
}

// ValidatedAttributeRequest는 검증된 속성 요청
type ValidatedAttributeRequest struct {
	Action     string                 `json:"action"`
	Attributes map[string]interface{} `json:"attributes"`
}

// Validate는 속성 요청 검증
func (req *ValidatedAttributeRequest) Validate(validator *InputValidator) error {
	// 액션 검증
	validActions := map[string]bool{
		"add":    true,
		"modify": true,
	}
	if !validActions[req.Action] {
		return &ValidationError{"action", "action must be 'add' or 'modify'"}
	}
	
	// 속성 검증
	if req.Attributes == nil || len(req.Attributes) == 0 {
		return &ValidationError{"attributes", "attributes cannot be empty"}
	}
	
	if err := validator.ValidateAttributes(req.Attributes); err != nil {
		return err
	}
	
	return nil
}

// ValidatedDeleteAttributeRequest는 검증된 속성 삭제 요청
type ValidatedDeleteAttributeRequest struct {
	AttributeName string `json:"attribute_name"`
}

// Validate는 속성 삭제 요청 검증
func (req *ValidatedDeleteAttributeRequest) Validate(validator *InputValidator) error {
	if err := validator.ValidateAttributeName(req.AttributeName); err != nil {
		return err
	}
	
	return nil
}

// ValidatedRekeyRequest는 검증된 키 재생성 요청
type ValidatedRekeyRequest struct {
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Validate는 키 재생성 요청 검증
func (req *ValidatedRekeyRequest) Validate(validator *InputValidator) error {
	// 속성 검증 (선택적)
	if req.Attributes != nil {
		if err := validator.ValidateAttributes(req.Attributes); err != nil {
			return err
		}
	}
	
	return nil
}

// ValidatedRemoteClusterRequest는 검증된 원격 클러스터 요청
type ValidatedRemoteClusterRequest struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Endpoints     []string `json:"endpoints"`
	Enabled       bool     `json:"enabled"`
	Priority      int      `json:"priority"`
	Bidirectional bool     `json:"bidirectional"`
	APIKey        string   `json:"api_key,omitempty"`
	TLSEnabled    bool     `json:"tls_enabled"`
}

// Validate는 원격 클러스터 요청 검증
func (req *ValidatedRemoteClusterRequest) Validate(validator *InputValidator) error {
	// 클러스터 ID 검증
	if err := validator.ValidateClusterID(req.ID); err != nil {
		return err
	}
	
	// 이름 검증
	if req.Name == "" {
		return &ValidationError{"name", "name is required"}
	}
	req.Name = validator.SanitizeString(req.Name)
	if len(req.Name) > MaxStringLength {
		return &ValidationError{"name", "name too long"}
	}
	
	// 엔드포인트 검증
	if len(req.Endpoints) == 0 {
		return &ValidationError{"endpoints", "at least one endpoint is required"}
	}
	if len(req.Endpoints) > 10 {
		return &ValidationError{"endpoints", "too many endpoints (max 10)"}
	}
	
	for i, endpoint := range req.Endpoints {
		if err := validator.ValidateURL(endpoint); err != nil {
			return &ValidationError{"endpoints", fmt.Sprintf("invalid endpoint[%d]: %v", i, err)}
		}
	}
	
	// 우선순위 검증
	if req.Priority < 1 || req.Priority > 100 {
		return &ValidationError{"priority", "priority must be between 1 and 100"}
	}
	
	// API 키 검증 (선택적)
	if req.APIKey != "" {
		req.APIKey = validator.SanitizeString(req.APIKey)
		if len(req.APIKey) > MaxStringLength {
			return &ValidationError{"api_key", "api_key too long"}
		}
	}
	
	return nil
}

// readAndValidateJSON은 JSON 읽기 및 검증
func readAndValidateJSON(r *http.Request, v interface{}) error {
	validator := NewInputValidator()
	
	// Content-Length 검증
	if r.ContentLength > 0 {
		if err := validator.ValidateJSONSize(r.ContentLength); err != nil {
			return err
		}
	}
	
	// JSON 읽기 (크기 제한)
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	body := io.LimitReader(r.Body, maxBodySize)
	
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields() // 알 수 없는 필드 거부
	
	if err := decoder.Decode(v); err != nil {
		return &ValidationError{"json", fmt.Sprintf("invalid JSON: %v", err)}
	}
	
	return nil
}

// validateKeyID는 경로에서 추출한 키 ID 검증
func validateKeyID(keyID string) error {
	validator := NewInputValidator()
	return validator.ValidateKeyID(keyID)
}
