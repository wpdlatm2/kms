package main

import (
	"crypto/tls"
	"embed"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

//go:embed web
var webContent embed.FS

func main() {
	// 웹 파일 시스템 설정
	webFS, err := fs.Sub(webContent, "web")
	if err != nil {
		log.Fatal(err)
	}

	// 정적 파일 서빙
	http.Handle("/", http.FileServer(http.FS(webFS)))

	// API 프록시 (CORS 포함)
	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		// CORS 헤더
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, X-Client-ID, X-Group-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// API 서버로 프록시
		proxyToAPIServer(w, r)
	})

	// TLS 설정 여부 확인
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	if certFile == "" {
		certFile = "certs/server.crt"
	}
	if keyFile == "" {
		keyFile = "certs/server.key"
	}

	// 인증서 파일 존재 확인
	if fileExists(certFile) && fileExists(keyFile) {
		log.Println("🔒 HTTPS 모드로 시작")
		log.Printf("📁 인증서: %s", certFile)
		log.Printf("🔑 키 파일: %s", keyFile)
		
		// TLS 설정
		tlsConfig := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		}

		server := &http.Server{
			Addr:      ":8443",
			TLSConfig: tlsConfig,
		}

		// HTTP -> HTTPS 리다이렉트 서버 시작
		go func() {
			log.Println("🔓 HTTP 리다이렉트 서버 시작: http://localhost:8080 -> https://localhost:8443")
			if err := http.ListenAndServe(":8080", http.HandlerFunc(redirectToHTTPS)); err != nil {
				log.Printf("HTTP 리다이렉트 서버 오류: %v", err)
			}
		}()

		log.Println("🌐 웹 UI 서버 시작: https://localhost:8443")
		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	} else {
		log.Println("⚠️  TLS 인증서를 찾을 수 없습니다. HTTP 모드로 시작합니다.")
		log.Println("💡 HTTPS를 사용하려면 다음 명령어로 인증서를 생성하세요:")
		log.Println("   make generate-certs")
		log.Println("   또는")
		log.Println("   ./scripts/generate-certs.sh")
		log.Println("")
		log.Println("🌐 웹 UI 서버 시작: http://localhost:8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}
}

// redirectToHTTPS는 HTTP를 HTTPS로 리다이렉트
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// fileExists는 파일 존재 여부 확인
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func proxyToAPIServer(w http.ResponseWriter, r *http.Request) {
	// API 서버 URL
	apiURL := "http://localhost:9090" + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		apiURL += "?" + r.URL.RawQuery
	}

	// 요청 전달
	client := &http.Client{}
	proxyReq, err := http.NewRequest(r.Method, apiURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 헤더 복사
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// 요청 실행
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 응답 헤더 복사
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 상태 코드 설정
	w.WriteHeader(resp.StatusCode)

	// 응답 본문 복사
	_, _ = io.Copy(w, resp.Body)
}
