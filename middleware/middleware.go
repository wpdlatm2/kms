package middleware

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// Middleware는 HTTP 핸들러를 감싸는 함수
type Middleware func(http.Handler) http.Handler

// Chain은 여러 미들웨어를 체인으로 연결
func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// Logging은 요청 로깅 미들웨어
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// 커스텀 ResponseWriter로 상태 코드 캡처
		lrw := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		
		// 다음 핸들러 실행
		next.ServeHTTP(lrw, r)
		
		// 로그 출력
		duration := time.Since(start)
		log.Printf(
			"%s %s %s %d %s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			lrw.statusCode,
			duration,
		)
	})
}

// loggingResponseWriter는 상태 코드를 캡처하는 ResponseWriter
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// CORS는 CORS 헤더를 추가하는 미들웨어
func CORS(allowOrigin string, allowMethods []string, allowHeaders []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS 헤더 설정
			if allowOrigin == "" {
				allowOrigin = "*"
			}
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			
			if len(allowMethods) > 0 {
				methods := ""
				for i, method := range allowMethods {
					if i > 0 {
						methods += ", "
					}
					methods += method
				}
				w.Header().Set("Access-Control-Allow-Methods", methods)
			} else {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}
			
			if len(allowHeaders) > 0 {
				headers := ""
				for i, header := range allowHeaders {
					if i > 0 {
						headers += ", "
					}
					headers += header
				}
				w.Header().Set("Access-Control-Allow-Headers", headers)
			} else {
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Client-ID, X-Group-ID")
			}
			
			w.Header().Set("Access-Control-Max-Age", "86400")
			
			// Preflight 요청 처리
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders는 보안 헤더를 추가하는 미들웨어
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 보안 헤더 설정
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		next.ServeHTTP(w, r)
	})
}

// Recovery는 패닉 복구 미들웨어
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PANIC: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		
		next.ServeHTTP(w, r)
	})
}

// Timeout은 요청 타임아웃 미들웨어
func Timeout(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 타임아웃 컨텍스트 생성
			ctx := r.Context()
			ctx, cancel := timeoutContext(ctx, timeout)
			defer cancel()
			
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID는 요청 ID를 생성하는 미들웨어
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 요청 ID 생성
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		
		// 헤더에 추가
		w.Header().Set("X-Request-ID", requestID)
		
		// 컨텍스트에 추가 (필요시)
		ctx := contextWithRequestID(r.Context(), requestID)
		r = r.WithContext(ctx)
		
		next.ServeHTTP(w, r)
	})
}

// RateLimiter는 요청 속도 제한 미들웨어
type RateLimiter struct {
	requests map[string]*rateLimitEntry
	maxReqs  int
	window   time.Duration
}

type rateLimitEntry struct {
	count     int
	resetTime time.Time
}

func NewRateLimiter(maxReqs int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string]*rateLimitEntry),
		maxReqs:  maxReqs,
		window:   window,
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 클라이언트 식별 (IP 주소 또는 API 키)
		clientID := getClientIdentifier(r)
		
		// 현재 시간
		now := time.Now()
		
		// 엔트리 확인
		entry, exists := rl.requests[clientID]
		if !exists || now.After(entry.resetTime) {
			// 새로운 윈도우 시작
			rl.requests[clientID] = &rateLimitEntry{
				count:     1,
				resetTime: now.Add(rl.window),
			}
			next.ServeHTTP(w, r)
			return
		}
		
		// 요청 카운트 증가
		if entry.count >= rl.maxReqs {
			// 제한 초과
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.maxReqs))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", entry.resetTime.Unix()))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		
		entry.count++
		
		// 헤더 설정
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.maxReqs))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", rl.maxReqs-entry.count))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", entry.resetTime.Unix()))
		
		next.ServeHTTP(w, r)
	})
}

// RequestSizeLimit은 요청 크기 제한 미들웨어
func RequestSizeLimit(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Content-Length 확인
			if r.ContentLength > maxBytes {
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			
			// Body 크기 제한
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			
			next.ServeHTTP(w, r)
		})
	}
}

// Compression은 응답 압축 미들웨어 (Gzip)
func Compression(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept-Encoding 헤더 확인
		if !acceptsGzip(r) {
			next.ServeHTTP(w, r)
			return
		}
		
		// Gzip writer 생성
		gz := getGzipWriter(w)
		defer putGzipWriter(gz)
		
		gz.Reset(w)
		defer gz.Close()
		
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		
		gzw := &gzipResponseWriter{
			ResponseWriter: w,
			Writer:         gz,
		}
		
		next.ServeHTTP(gzw, r)
	})
}

// HealthCheck는 특정 경로에 대한 헬스체크 미들웨어
func HealthCheck(path string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == path {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// 헬퍼 함수들

func getClientIdentifier(r *http.Request) string {
	// API 키가 있으면 사용
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}
	
	// 클라이언트 ID가 있으면 사용
	if clientID := r.Header.Get("X-Client-ID"); clientID != "" {
		return clientID
	}
	
	// IP 주소 사용
	return getClientIP(r)
}

func getClientIP(r *http.Request) string {
	// X-Forwarded-For 헤더 확인
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	
	// X-Real-IP 헤더 확인
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// RemoteAddr 사용
	return r.RemoteAddr
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// 컨텍스트 관련 헬퍼 함수들은 별도 파일에 구현
func contextWithRequestID(ctx interface{}, requestID string) interface{} {
	// 실제 구현에서는 context.Context 사용
	return ctx
}

func timeoutContext(ctx interface{}, timeout time.Duration) (interface{}, func()) {
	// 실제 구현에서는 context.WithTimeout 사용
	return ctx, func() {}
}

func acceptsGzip(r *http.Request) bool {
	// Accept-Encoding 헤더에서 gzip 확인
	encoding := r.Header.Get("Accept-Encoding")
	return contains(encoding, "gzip")
}

func contains(s, substr string) bool {
	// 간단한 문자열 포함 확인
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
		 (s[:len(substr)] == substr || 
		  s[len(s)-len(substr):] == substr)))
}

// Gzip writer pool (실제 구현 필요)
type gzipWriter struct {
	http.ResponseWriter
	Writer interface{}
}

func getGzipWriter(w http.ResponseWriter) *gzipWriter {
	return &gzipWriter{ResponseWriter: w}
}

func putGzipWriter(gz *gzipWriter) {
	// Writer pool에 반환
}

func (gz *gzipWriter) Reset(w http.ResponseWriter) {
	// Writer 리셋
}

func (gz *gzipWriter) Close() error {
	// Writer 닫기
	return nil
}

type gzipResponseWriter struct {
	http.ResponseWriter
	Writer interface{}
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	// 실제로는 gzip.Writer.Write 호출
	return w.ResponseWriter.Write(b)
}
