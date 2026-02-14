package kmip

import (
	"testing"
)

// TestValidateAlgorithm 알고리즘 검증 테스트
func TestValidateAlgorithm(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		// 정상 케이스
		{"Valid AES", "AES", false},
		{"Valid RSA", "RSA", false},
		{"Valid 3DES", "3DES", false},
		{"Valid SEED", "SEED", false},
		
		// 비정상 케이스
		{"Empty algorithm", "", true},
		{"Invalid algorithm", "INVALID", true},
		{"SQL Injection", "AES'; DROP TABLE keys--", true},
		{"XSS attempt", "<script>alert('xss')</script>", true},
		{"Special chars", "AES@#$%", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateAlgorithm(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateKeyLength 키 길이 검증 테스트
func TestValidateKeyLength(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name      string
		algorithm string
		length    int32
		wantErr   bool
	}{
		// 정상 케이스
		{"Valid AES-128", "AES", 128, false},
		{"Valid AES-256", "AES", 256, false},
		{"Valid RSA-2048", "RSA", 2048, false},
		{"Valid SEED-128", "SEED", 128, false},
		
		// 비정상 케이스
		{"Too small", "AES", 1, true},
		{"Too large", "AES", 10000, true},
		{"Invalid AES length", "AES", 129, true},
		{"Invalid RSA length", "RSA", 1025, true},
		{"Negative length", "AES", -128, true},
		{"Zero length", "AES", 0, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateKeyLength(tt.algorithm, tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyLength() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateKeyMaterial 키 자료 검증 테스트
func TestValidateKeyMaterial(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name        string
		keyMaterial string
		wantErr     bool
	}{
		// 정상 케이스
		{"Valid hex", "0123456789ABCDEF", false},
		{"Valid lowercase hex", "abcdef0123456789", false},
		{"Valid mixed case", "AbCdEf0123456789", false},
		
		// 비정상 케이스
		{"Empty", "", true},
		{"Odd length", "123", true},
		{"Invalid chars", "GHIJKLMN", true},
		{"With spaces", "01 23 45 67", true},
		{"With hyphens", "01-23-45-67", true},
		{"SQL Injection", "'; DROP TABLE keys--", true},
		{"Path traversal", "../../../etc/passwd", true},
		{"Null bytes", "0123\x00456", true},
		{"Too long", string(make([]byte, MaxKeyMaterialLength+10)), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateKeyMaterial(tt.keyMaterial)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyMaterial() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateKeyID 키 ID 검증 테스트
func TestValidateKeyID(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name    string
		keyID   string
		wantErr bool
	}{
		// 정상 케이스
		{"Valid UUID style", "550e8400-e29b-41d4-a716-446655440000", false},
		{"Valid alphanumeric", "key123", false},
		{"With hyphens", "my-key-123", false},
		{"With underscores", "my_key_123", false},
		
		// 비정상 케이스
		{"Empty", "", true},
		{"With spaces", "my key 123", true},
		{"With special chars", "key@123", true},
		{"SQL Injection", "key'; DROP TABLE--", true},
		{"XSS", "<script>alert(1)</script>", true},
		{"Path traversal", "../../../etc/passwd", true},
		{"Command injection", "key; rm -rf /", true},
		{"Too long", string(make([]byte, MaxStringLength+10)), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateKeyID(tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateAttributes 속성 검증 테스트
func TestValidateAttributes(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name       string
		attributes map[string]interface{}
		wantErr    bool
	}{
		// 정상 케이스
		{
			name: "Valid attributes",
			attributes: map[string]interface{}{
				"environment": "production",
				"owner":       "john.doe",
			},
			wantErr: false,
		},
		{
			name: "With numbers",
			attributes: map[string]interface{}{
				"version": 1,
				"count":   100,
			},
			wantErr: false,
		},
		
		// 비정상 케이스
		{
			name: "Too many attributes",
			attributes: func() map[string]interface{} {
				attrs := make(map[string]interface{})
				for i := 0; i < MaxAttributeCount+10; i++ {
					attrs[fmt.Sprintf("key%d", i)] = "value"
				}
				return attrs
			}(),
			wantErr: true,
		},
		{
			name: "SQL Injection in key",
			attributes: map[string]interface{}{
				"key'; DROP TABLE--": "value",
			},
			wantErr: true,
		},
		{
			name: "SQL Injection in value",
			attributes: map[string]interface{}{
				"key": "'; DROP TABLE users--",
			},
			wantErr: true,
		},
		{
			name: "XSS in value",
			attributes: map[string]interface{}{
				"description": "<script>alert('xss')</script>",
			},
			wantErr: true,
		},
		{
			name: "Too long key",
			attributes: map[string]interface{}{
				string(make([]byte, MaxAttributeKeyLen+10)): "value",
			},
			wantErr: true,
		},
		{
			name: "Too long value",
			attributes: map[string]interface{}{
				"key": string(make([]byte, MaxAttributeValueLen+10)),
			},
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateAttributes(tt.attributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAttributes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateSearchLimit 검색 제한 검증 테스트
func TestValidateSearchLimit(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name    string
		limit   *int32
		wantErr bool
	}{
		{"Nil limit", nil, false},
		{"Valid limit 10", ptr(int32(10)), false},
		{"Valid limit 1000", ptr(int32(1000)), false},
		{"Zero limit", ptr(int32(0)), true},
		{"Negative limit", ptr(int32(-1)), true},
		{"Too large", ptr(int32(MaxSearchResults + 100)), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateSearchLimit(tt.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSearchLimit() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateHostname 호스트네임 검증 테스트
func TestValidateHostname(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		// 정상 케이스
		{"Valid IP", "192.168.1.1", false},
		{"Valid hostname", "example.com", false},
		{"Valid subdomain", "api.example.com", false},
		{"Valid localhost", "localhost", false},
		
		// 비정상 케이스
		{"Empty", "", true},
		{"Invalid IP", "999.999.999.999", true},
		{"Invalid chars", "example@.com", true},
		{"SQL Injection", "example.com'; DROP--", true},
		{"Path traversal", "../../../etc/hosts", true},
		{"Too long", string(make([]byte, 300)) + ".com", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateHostname(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidatePort 포트 검증 테스트
func TestValidatePort(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"Valid port 80", 80, false},
		{"Valid port 443", 443, false},
		{"Valid port 8080", 8080, false},
		{"Valid port 65535", 65535, false},
		{"Zero port", 0, true},
		{"Negative port", -1, true},
		{"Too large", 65536, true},
		{"Very large", 100000, true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSanitizeString 문자열 정제 테스트
func TestSanitizeString(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Trim spaces", "  hello  ", "hello"},
		{"Remove null bytes", "hello\x00world", "helloworld"},
		{"Remove control chars", "hello\x01\x02world", "helloworld"},
		{"Keep newlines", "hello\nworld", "hello\nworld"},
		{"Keep tabs", "hello\tworld", "hello\tworld"},
		{"Mixed", "  \x00hello\x01\nworld\x02  ", "hello\nworld"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestContainsDangerousPattern 위험 패턴 검사 테스트
func TestContainsDangerousPattern(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name      string
		input     string
		dangerous bool
	}{
		// 안전한 입력
		{"Safe string", "hello world", false},
		{"Safe with numbers", "key123", false},
		
		// 위험한 입력
		{"SQL comment", "key-- comment", true},
		{"SQL injection", "key' OR '1'='1", true},
		{"XSS script", "<script>alert(1)</script>", true},
		{"JavaScript", "javascript:alert(1)", true},
		{"Path traversal", "../../../etc/passwd", true},
		{"Null byte", "key\x00value", true},
		{"SQL UNION", "UNION SELECT * FROM users", true},
		{"SQL DROP", "DROP TABLE keys", true},
		{"XSS onerror", "<img onerror='alert(1)'>", true},
		{"XSS onload", "<body onload='alert(1)'>", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.containsDangerousPattern(tt.input)
			if result != tt.dangerous {
				t.Errorf("containsDangerousPattern() = %v, want %v", result, tt.dangerous)
			}
		})
	}
}

// TestValidateEmail 이메일 검증 테스트
func TestValidateEmail(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"Valid email", "user@example.com", false},
		{"Valid with subdomain", "user@mail.example.com", false},
		{"Empty (optional)", "", false},
		{"Invalid format", "invalid-email", true},
		{"Missing @", "userexample.com", true},
		{"Missing domain", "user@", true},
		{"With spaces", "user @example.com", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateURL URL 검증 테스트
func TestValidateURL(t *testing.T) {
	validator := NewInputValidator()
	
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"Valid HTTP", "http://example.com", false},
		{"Valid HTTPS", "https://example.com", false},
		{"With path", "https://example.com/path", false},
		{"With port", "https://example.com:8080", false},
		{"Empty (optional)", "", false},
		{"Invalid protocol", "ftp://example.com", true},
		{"Missing protocol", "example.com", true},
		{"With spaces", "http://example .com", true},
		{"JavaScript", "javascript:alert(1)", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper function
func ptr[T any](v T) *T {
	return &v
}
