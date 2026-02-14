package kmip

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ValidationError는 검증 오류
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
}

// InputValidator는 입력값 검증기
type InputValidator struct{}

// NewInputValidator는 새로운 검증기를 생성
func NewInputValidator() *InputValidator {
	return &InputValidator{}
}

// 정규표현식 패턴
var (
	// 알파벳, 숫자, 하이픈, 언더스코어만 허용
	alphanumericPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	
	// UUID 형식
	uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	
	// Hex 문자열 (0-9, a-f, A-F)
	hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	
	// 안전한 문자열 (알파벳, 숫자, 공백, 일부 특수문자)
	safeStringPattern = regexp.MustCompile(`^[a-zA-Z0-9\s\-_.,:/@]+$`)
	
	// IP 주소
	ipPattern = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	
	// 호스트네임
	hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

// 입력값 제한
const (
	MaxStringLength      = 1024      // 일반 문자열 최대 길이
	MaxKeyMaterialLength = 1024 * 10 // 키 자료 최대 길이 (10KB)
	MaxAttributeCount    = 100       // 최대 속성 개수
	MaxAttributeKeyLen   = 256       // 속성 키 최대 길이
	MaxAttributeValueLen = 2048      // 속성 값 최대 길이
	MaxSearchResults     = 1000      // 최대 검색 결과 수
	
	MinKeyLength = 8   // 최소 키 길이 (비트)
	MaxKeyLength = 4096 // 최대 키 길이 (비트)
	
	MinPasswordLength = 8  // 최소 비밀번호 길이
	MaxPasswordLength = 128 // 최대 비밀번호 길이
)

// ValidateAlgorithm은 알고리즘 검증
func (v *InputValidator) ValidateAlgorithm(algorithm string) error {
	if algorithm == "" {
		return &ValidationError{"algorithm", "algorithm is required"}
	}
	
	validAlgorithms := map[string]bool{
		"DES":      true,
		"3DES":     true,
		"AES":      true,
		"RSA":      true,
		"DSA":      true,
		"ECDSA":    true,
		"ECDH":     true,
		"DH":       true,
		"HMAC-SHA1": true,
		"HMAC-SHA256": true,
		"HMAC-SHA384": true,
		"HMAC-SHA512": true,
		"SEED":     true,
		"ARIA":     true,
	}
	
	if !validAlgorithms[algorithm] {
		return &ValidationError{"algorithm", fmt.Sprintf("invalid algorithm: %s", algorithm)}
	}
	
	return nil
}

// ValidateKeyLength는 키 길이 검증
func (v *InputValidator) ValidateKeyLength(algorithm string, length int32) error {
	if length < MinKeyLength {
		return &ValidationError{"length", fmt.Sprintf("key length must be at least %d bits", MinKeyLength)}
	}
	
	if length > MaxKeyLength {
		return &ValidationError{"length", fmt.Sprintf("key length must not exceed %d bits", MaxKeyLength)}
	}
	
	// 알고리즘별 유효한 키 길이
	validLengths := map[string][]int32{
		"DES":  {56},
		"3DES": {112, 168, 192},
		"AES":  {128, 192, 256},
		"RSA":  {1024, 2048, 3072, 4096},
		"DSA":  {1024, 2048, 3072},
		"ECDSA": {256, 384, 521},
		"SEED": {128},
		"ARIA": {128, 192, 256},
	}
	
	if lengths, ok := validLengths[algorithm]; ok {
		valid := false
		for _, l := range lengths {
			if length == l {
				valid = true
				break
			}
		}
		if !valid {
			return &ValidationError{"length", fmt.Sprintf("invalid key length for %s: %d (valid: %v)", algorithm, length, lengths)}
		}
	}
	
	return nil
}

// ValidateKeyMaterial은 키 자료 검증
func (v *InputValidator) ValidateKeyMaterial(keyMaterial string) error {
	if keyMaterial == "" {
		return &ValidationError{"key_material", "key material is required"}
	}
	
	if len(keyMaterial) > MaxKeyMaterialLength {
		return &ValidationError{"key_material", fmt.Sprintf("key material too long (max %d characters)", MaxKeyMaterialLength)}
	}
	
	// Hex 문자열 검증
	if !hexPattern.MatchString(keyMaterial) {
		return &ValidationError{"key_material", "key material must be a valid hex string"}
	}
	
	// 짝수 길이 확인 (바이트 단위)
	if len(keyMaterial)%2 != 0 {
		return &ValidationError{"key_material", "key material must have even length (full bytes)"}
	}
	
	return nil
}

// ValidateKeyID는 키 ID 검증
func (v *InputValidator) ValidateKeyID(keyID string) error {
	if keyID == "" {
		return &ValidationError{"key_id", "key ID is required"}
	}
	
	if len(keyID) > MaxStringLength {
		return &ValidationError{"key_id", fmt.Sprintf("key ID too long (max %d characters)", MaxStringLength)}
	}
	
	// 안전한 문자만 허용
	if !alphanumericPattern.MatchString(keyID) {
		return &ValidationError{"key_id", "key ID must contain only alphanumeric characters, hyphens, and underscores"}
	}
	
	return nil
}

// ValidateAttributeName은 속성 이름 검증
func (v *InputValidator) ValidateAttributeName(name string) error {
	if name == "" {
		return &ValidationError{"attribute_name", "attribute name is required"}
	}
	
	if len(name) > MaxAttributeKeyLen {
		return &ValidationError{"attribute_name", fmt.Sprintf("attribute name too long (max %d characters)", MaxAttributeKeyLen)}
	}
	
	// 안전한 문자만 허용
	if !safeStringPattern.MatchString(name) {
		return &ValidationError{"attribute_name", "attribute name contains invalid characters"}
	}
	
	return nil
}

// ValidateAttributeValue는 속성 값 검증
func (v *InputValidator) ValidateAttributeValue(value interface{}) error {
	if value == nil {
		return &ValidationError{"attribute_value", "attribute value cannot be nil"}
	}
	
	// 문자열 값 검증
	if str, ok := value.(string); ok {
		if len(str) > MaxAttributeValueLen {
			return &ValidationError{"attribute_value", fmt.Sprintf("attribute value too long (max %d characters)", MaxAttributeValueLen)}
		}
		
		// SQL Injection, XSS 방지
		if v.containsDangerousPattern(str) {
			return &ValidationError{"attribute_value", "attribute value contains potentially dangerous patterns"}
		}
	}
	
	return nil
}

// ValidateAttributes는 속성 맵 검증
func (v *InputValidator) ValidateAttributes(attributes map[string]interface{}) error {
	if len(attributes) > MaxAttributeCount {
		return &ValidationError{"attributes", fmt.Sprintf("too many attributes (max %d)", MaxAttributeCount)}
	}
	
	for key, value := range attributes {
		if err := v.ValidateAttributeName(key); err != nil {
			return err
		}
		
		if err := v.ValidateAttributeValue(value); err != nil {
			return err
		}
	}
	
	return nil
}

// ValidateSearchLimit는 검색 제한 검증
func (v *InputValidator) ValidateSearchLimit(limit *int32) error {
	if limit == nil {
		return nil
	}
	
	if *limit < 1 {
		return &ValidationError{"limit", "limit must be at least 1"}
	}
	
	if *limit > MaxSearchResults {
		return &ValidationError{"limit", fmt.Sprintf("limit too large (max %d)", MaxSearchResults)}
	}
	
	return nil
}

// ValidateOffset는 오프셋 검증
func (v *InputValidator) ValidateOffset(offset *int32) error {
	if offset == nil {
		return nil
	}
	
	if *offset < 0 {
		return &ValidationError{"offset", "offset cannot be negative"}
	}
	
	return nil
}

// ValidateHostname은 호스트네임 검증
func (v *InputValidator) ValidateHostname(hostname string) error {
	if hostname == "" {
		return &ValidationError{"hostname", "hostname is required"}
	}
	
	if len(hostname) > 253 {
		return &ValidationError{"hostname", "hostname too long (max 253 characters)"}
	}
	
	// IP 주소 또는 호스트네임
	if !ipPattern.MatchString(hostname) && !hostnamePattern.MatchString(hostname) {
		return &ValidationError{"hostname", "invalid hostname or IP address"}
	}
	
	return nil
}

// ValidatePort는 포트 번호 검증
func (v *InputValidator) ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return &ValidationError{"port", "port must be between 1 and 65535"}
	}
	
	return nil
}

// ValidateClusterID는 클러스터 ID 검증
func (v *InputValidator) ValidateClusterID(clusterID string) error {
	if clusterID == "" {
		return &ValidationError{"cluster_id", "cluster ID is required"}
	}
	
	if len(clusterID) > MaxStringLength {
		return &ValidationError{"cluster_id", "cluster ID too long"}
	}
	
	if !alphanumericPattern.MatchString(clusterID) {
		return &ValidationError{"cluster_id", "cluster ID must contain only alphanumeric characters, hyphens, and underscores"}
	}
	
	return nil
}

// ValidateReplicationMode는 복제 모드 검증
func (v *InputValidator) ValidateReplicationMode(mode string) error {
	validModes := map[string]bool{
		"sync":    true,
		"async":   true,
		"quorum":  true,
	}
	
	if !validModes[mode] {
		return &ValidationError{"replication_mode", fmt.Sprintf("invalid replication mode: %s (valid: sync, async, quorum)", mode)}
	}
	
	return nil
}

// SanitizeString은 문자열 정제
func (v *InputValidator) SanitizeString(s string) string {
	// 앞뒤 공백 제거
	s = strings.TrimSpace(s)
	
	// NULL 바이트 제거
	s = strings.ReplaceAll(s, "\x00", "")
	
	// 제어 문자 제거
	var builder strings.Builder
	for _, r := range s {
		if !unicode.IsControl(r) || r == '\n' || r == '\r' || r == '\t' {
			builder.WriteRune(r)
		}
	}
	
	return builder.String()
}

// containsDangerousPattern은 위험한 패턴 검사
func (v *InputValidator) containsDangerousPattern(s string) bool {
	dangerous := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
		"eval(",
		"exec(",
		"--",        // SQL comment
		";--",
		"/*",        // SQL comment
		"*/",
		"xp_",       // SQL extended procedures
		"sp_",       // SQL stored procedures
		"UNION",     // SQL injection
		"SELECT",    // SQL injection
		"INSERT",
		"UPDATE",
		"DELETE",
		"DROP",
		"CREATE",
		"ALTER",
		"../",       // Path traversal
		"..\\",
		"%00",       // NULL byte injection
		"\x00",
	}
	
	lower := strings.ToLower(s)
	for _, pattern := range dangerous {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// ValidateJSONSize는 JSON 요청 크기 검증
func (v *InputValidator) ValidateJSONSize(size int64) error {
	const maxJSONSize = 10 * 1024 * 1024 // 10MB
	
	if size > maxJSONSize {
		return &ValidationError{"request_size", fmt.Sprintf("request body too large (max %d bytes)", maxJSONSize)}
	}
	
	return nil
}

// ValidateEmail은 이메일 검증 (선택적)
func (v *InputValidator) ValidateEmail(email string) error {
	if email == "" {
		return nil
	}
	
	emailPattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailPattern.MatchString(email) {
		return &ValidationError{"email", "invalid email format"}
	}
	
	return nil
}

// ValidateURL은 URL 검증 (선택적)
func (v *InputValidator) ValidateURL(url string) error {
	if url == "" {
		return nil
	}
	
	urlPattern := regexp.MustCompile(`^https?://[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(/.*)?$`)
	if !urlPattern.MatchString(url) {
		return &ValidationError{"url", "invalid URL format"}
	}
	
	return nil
}
