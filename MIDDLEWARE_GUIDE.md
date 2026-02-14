# 🔧 Middleware 아키텍처 가이드

## 개요

Middleware를 **별도 패키지로 분리**하여 독립적으로 운영하고 재사용할 수 있도록 구성했습니다.

## 📁 디렉토리 구조

```
project/
├── middleware/              # 독립 미들웨어 패키지
│   ├── middleware.go        # 공통 미들웨어
│   ├── acl.go              # ACL 전용 미들웨어
│   ├── validation.go       # 입력 검증 미들웨어
│   └── audit.go            # 감사 로깅 미들웨어
│
├── kmip/                    # KMIP 서버 코드
│   ├── server.go
│   ├── rest_api.go
│   └── acl.go
│
└── cmd/
    └── kmip-server/
        └── main.go          # 미들웨어 조립
```

## 🎯 설계 원칙

### 1. 독립성 (Independence)
- 미들웨어는 비즈니스 로직과 분리
- 인터페이스를 통한 의존성 주입
- 다른 프로젝트에서도 재사용 가능

### 2. 조합성 (Composability)
- Chain 패턴으로 여러 미들웨어 조합
- 순서에 따라 다른 동작 가능
- 필요한 미들웨어만 선택적 사용

### 3. 확장성 (Extensibility)
- 새로운 미들웨어 쉽게 추가
- 기존 미들웨어 수정 없이 확장
- 플러그인 방식으로 동작

## 🔨 구현된 미들웨어

### 공통 미들웨어 (`middleware/middleware.go`)

#### 1. Logging
```go
// 요청/응답 로깅
handler := middleware.Logging(handler)
```

**기능:**
- 요청 메소드, URI, IP 주소 기록
- 응답 상태 코드 캡처
- 처리 시간 측정

#### 2. CORS
```go
// CORS 헤더 추가
corsMiddleware := middleware.CORS(
    "*",                                    // allowOrigin
    []string{"GET", "POST", "PUT", "DELETE"}, // allowMethods
    []string{"Content-Type", "X-API-Key"},  // allowHeaders
)
handler = corsMiddleware(handler)
```

**기능:**
- Access-Control-Allow-Origin 설정
- Preflight 요청 처리
- 커스텀 헤더 허용

#### 3. SecurityHeaders
```go
// 보안 헤더 추가
handler = middleware.SecurityHeaders(handler)
```

**설정 헤더:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: default-src 'self'`
- `Strict-Transport-Security: max-age=31536000`

#### 4. Recovery
```go
// 패닉 복구
handler = middleware.Recovery(handler)
```

**기능:**
- 패닉 발생 시 500 에러 반환
- 로그 기록
- 서버 다운 방지

#### 5. RateLimiter
```go
// 속도 제한 (100 req/min)
limiter := middleware.NewRateLimiter(100, time.Minute)
handler = limiter.Middleware(handler)
```

**기능:**
- IP 또는 API 키 기반 제한
- 윈도우 기반 카운팅
- X-RateLimit 헤더 반환

#### 6. RequestSizeLimit
```go
// 요청 크기 제한 (10MB)
handler = middleware.RequestSizeLimit(10 * 1024 * 1024)(handler)
```

**기능:**
- Content-Length 확인
- Body 크기 제한
- 413 에러 반환

#### 7. Timeout
```go
// 요청 타임아웃 (30초)
handler = middleware.Timeout(30 * time.Second)(handler)
```

**기능:**
- 컨텍스트 기반 타임아웃
- 긴 요청 자동 종료

#### 8. RequestID
```go
// 요청 ID 생성
handler = middleware.RequestID(handler)
```

**기능:**
- 고유 요청 ID 생성
- X-Request-ID 헤더 추가
- 로그 추적 용이

### ACL 미들웨어 (`middleware/acl.go`)

#### 1. RequirePermission
```go
// 특정 권한 요구
aclMW := middleware.NewACLMiddleware(aclManager, auditLogger)
handler = aclMW.RequirePermission("keys", "CREATE")(handler)
```

**기능:**
- 권한 확인
- 감사 로그 자동 기록
- 403 에러 반환

#### 2. RequireAdmin
```go
// Admin 권한 요구
handler = aclMW.RequireAdmin()(handler)
```

#### 3. RequireOwner
```go
// Owner 권한 요구
handler = aclMW.RequireOwner("keys")(handler)
```

#### 4. RequireGuest
```go
// Guest 권한 (READ) 요구
handler = aclMW.RequireGuest("keys")(handler)
```

#### 5. RequireAudit
```go
// Audit 권한 요구
handler = aclMW.RequireAudit()(handler)
```

## 🔧 사용 방법

### 기본 사용

```go
package main

import (
    "net/http"
    "time"
    
    "your-project/middleware"
)

func main() {
    // 핸들러 생성
    mux := http.NewServeMux()
    mux.HandleFunc("/api/v1/keys", handleKeys)
    
    // 미들웨어 체인 구성
    handler := middleware.Chain(
        mux,
        middleware.Recovery,           // 1. 패닉 복구 (최외곽)
        middleware.Logging,            // 2. 로깅
        middleware.RequestID,          // 3. 요청 ID
        middleware.SecurityHeaders,    // 4. 보안 헤더
        middleware.CORS("*", nil, nil), // 5. CORS
        middleware.RequestSizeLimit(10*1024*1024), // 6. 크기 제한
        middleware.Timeout(30*time.Second),        // 7. 타임아웃
    )
    
    // 서버 시작
    http.ListenAndServe(":8080", handler)
}
```

### ACL과 함께 사용

```go
package main

import (
    "net/http"
    
    "your-project/middleware"
    "your-project/kmip"
)

func main() {
    // ACL 매니저 생성
    aclManager := kmip.NewACLManager()
    auditLogger := kmip.NewAuditLogger(10000, 30*24*time.Hour)
    
    // ACL 미들웨어 생성
    aclMW := middleware.NewACLMiddleware(aclManager, auditLogger)
    
    // 엔드포인트별 권한 설정
    mux := http.NewServeMux()
    
    // 키 생성 - Owner 권한 필요
    mux.Handle("/api/v1/keys", 
        aclMW.RequireOwner("keys")(
            http.HandlerFunc(handleCreateKey)))
    
    // 키 조회 - Guest 권한 필요
    mux.Handle("/api/v1/keys/", 
        aclMW.RequireGuest("keys")(
            http.HandlerFunc(handleGetKey)))
    
    // 그룹 관리 - Admin 권한 필요
    mux.Handle("/api/v1/groups", 
        aclMW.RequireAdmin()(
            http.HandlerFunc(handleGroups)))
    
    // 감사 로그 - Audit 권한 필요
    mux.Handle("/api/v1/audit/logs", 
        aclMW.RequireAudit()(
            http.HandlerFunc(handleAuditLogs)))
    
    // 공통 미들웨어 적용
    handler := middleware.Chain(
        mux,
        middleware.Recovery,
        middleware.Logging,
        middleware.SecurityHeaders,
    )
    
    http.ListenAndServe(":9090", handler)
}
```

### Rate Limiting 추가

```go
// Rate limiter 생성 (100 req/min)
limiter := middleware.NewRateLimiter(100, time.Minute)

// 미들웨어 체인에 추가
handler := middleware.Chain(
    mux,
    middleware.Recovery,
    middleware.Logging,
    limiter.Middleware,  // Rate limiting
    middleware.SecurityHeaders,
)
```

### 커스텀 미들웨어 작성

```go
// 커스텀 미들웨어
func CustomMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 전처리
        log.Println("Before request")
        
        // 다음 핸들러 실행
        next.ServeHTTP(w, r)
        
        // 후처리
        log.Println("After request")
    })
}

// 사용
handler := middleware.Chain(
    mux,
    CustomMiddleware,  // 커스텀 미들웨어
    middleware.Logging,
)
```

## 📊 미들웨어 순서

**권장 순서 (외부 → 내부):**

```
1. Recovery          ← 가장 바깥 (모든 패닉 캡처)
2. Logging           ← 모든 요청 로깅
3. RequestID         ← 요청 추적
4. SecurityHeaders   ← 보안 헤더
5. CORS              ← CORS 처리
6. RateLimiter       ← 속도 제한
7. RequestSizeLimit  ← 크기 제한
8. Timeout           ← 타임아웃
9. ACL/Authorization ← 권한 확인
10. 비즈니스 로직     ← 실제 핸들러
```

**실행 흐름:**
```
요청 → Recovery → Logging → RequestID → ... → ACL → 핸들러
                                                      ↓
응답 ← Recovery ← Logging ← RequestID ← ... ← ACL ← 핸들러
```

## 🔍 인터페이스 기반 설계

### ACLChecker 인터페이스

```go
type ACLChecker interface {
    CheckPermission(clientID, groupID, resourceID string, permission string) bool
}
```

**구현 예:**
```go
type MyACLManager struct {
    // ...
}

func (m *MyACLManager) CheckPermission(clientID, groupID, resourceID string, permission string) bool {
    // ACL 확인 로직
    return true
}
```

### AuditLogger 인터페이스

```go
type AuditLogger interface {
    Log(log *AuditLog)
}
```

**구현 예:**
```go
type MyAuditLogger struct {
    // ...
}

func (l *MyAuditLogger) Log(log *AuditLog) {
    // 로그 저장 로직
}
```

## 🎯 실전 예제

### 예제 1: REST API 서버

```go
package main

import (
    "net/http"
    "time"
    
    "your-project/middleware"
    "your-project/kmip"
)

func main() {
    // 의존성 생성
    aclManager := kmip.NewACLManager()
    auditLogger := kmip.NewAuditLogger(10000, 30*24*time.Hour)
    rateLimiter := middleware.NewRateLimiter(1000, time.Minute)
    aclMW := middleware.NewACLMiddleware(aclManager, auditLogger)
    
    // 라우터 설정
    mux := http.NewServeMux()
    
    // Public 엔드포인트
    mux.HandleFunc("/health", handleHealth)
    
    // Protected 엔드포인트
    mux.Handle("/api/v1/keys", 
        aclMW.RequireOwner("keys")(
            http.HandlerFunc(handleKeys)))
    
    mux.Handle("/api/v1/admin/users",
        aclMW.RequireAdmin()(
            http.HandlerFunc(handleUsers)))
    
    // 글로벌 미들웨어 적용
    handler := middleware.Chain(
        mux,
        middleware.Recovery,
        middleware.Logging,
        middleware.RequestID,
        middleware.SecurityHeaders,
        middleware.CORS("*", nil, nil),
        rateLimiter.Middleware,
        middleware.RequestSizeLimit(10*1024*1024),
        middleware.Timeout(30*time.Second),
    )
    
    // 서버 시작
    http.ListenAndServe(":9090", handler)
}
```

### 예제 2: 엔드포인트별 다른 미들웨어

```go
// Admin API - 엄격한 제한
adminAPI := middleware.Chain(
    http.HandlerFunc(handleAdmin),
    aclMW.RequireAdmin(),
    middleware.RateLimiter(10, time.Minute), // 10 req/min
)

// Public API - 느슨한 제한  
publicAPI := middleware.Chain(
    http.HandlerFunc(handlePublic),
    middleware.RateLimiter(1000, time.Minute), // 1000 req/min
)

mux.Handle("/api/admin", adminAPI)
mux.Handle("/api/public", publicAPI)
```

## 🔒 보안 Best Practices

### 1. 미들웨어 순서 준수
```go
// ❌ 잘못된 순서
handler := middleware.Chain(
    mux,
    aclMW.RequireAdmin(),  // ACL이 Logging보다 먼저!
    middleware.Logging,     // 거부된 요청이 로깅 안됨
)

// ✅ 올바른 순서
handler := middleware.Chain(
    mux,
    middleware.Logging,     // 먼저 로깅
    aclMW.RequireAdmin(),  // 그 다음 ACL
)
```

### 2. Rate Limiting 적용
```go
// 모든 API에 적용
limiter := middleware.NewRateLimiter(1000, time.Minute)
handler = limiter.Middleware(handler)
```

### 3. 요청 크기 제한
```go
// DoS 공격 방지
handler = middleware.RequestSizeLimit(10*1024*1024)(handler)
```

### 4. 타임아웃 설정
```go
// 긴 요청 방지
handler = middleware.Timeout(30*time.Second)(handler)
```

## 📝 테스트

### 미들웨어 테스트

```go
package middleware

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestLogging(t *testing.T) {
    // 테스트 핸들러
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    
    // 미들웨어 적용
    wrapped := Logging(handler)
    
    // 테스트 요청
    req := httptest.NewRequest("GET", "/test", nil)
    rec := httptest.NewRecorder()
    
    wrapped.ServeHTTP(rec, req)
    
    // 검증
    if rec.Code != http.StatusOK {
        t.Errorf("Expected 200, got %d", rec.Code)
    }
}
```

## 🎉 요약

```
✅ 독립적인 미들웨어 패키지
✅ 인터페이스 기반 설계
✅ Chain 패턴으로 조합 가능
✅ 재사용 가능한 컴포넌트
✅ ACL 전용 미들웨어 분리
✅ 감사 로깅 자동화
✅ 보안 Best Practices
✅ 테스트 가능한 구조
```

**Middleware를 독립적으로 관리하여 코드 품질과 재사용성을 높이세요!** 🔧✨
