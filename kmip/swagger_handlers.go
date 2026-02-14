package kmip

import (
	"net/http"
)

// SetupSwaggerRoutes는 Swagger 관련 라우트를 설정
func (api *RESTAPIServer) SetupSwaggerRoutes(mux *http.ServeMux) {
	// Swagger UI 페이지
	mux.HandleFunc("/docs", api.handleSwaggerUI)
	mux.HandleFunc("/docs/", api.handleSwaggerUI)
	
	// OpenAPI 스펙 (YAML)
	mux.HandleFunc("/api/v1/swagger.yaml", api.handleSwaggerSpec)
	
	// OpenAPI 스펙 (JSON)
	mux.HandleFunc("/api/v1/swagger.json", api.handleSwaggerJSON)
	
	// Redoc 페이지 (대안 문서 UI)
	mux.HandleFunc("/redoc", api.handleRedoc)
}

// handleSwaggerUI는 Swagger UI HTML 페이지를 제공
func (api *RESTAPIServer) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(SwaggerUIHTML))
}

// handleSwaggerSpec은 OpenAPI 스펙을 YAML 형식으로 제공
func (api *RESTAPIServer) handleSwaggerSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(OpenAPISpec))
}

// handleSwaggerJSON은 OpenAPI 스펙을 JSON 형식으로 제공
func (api *RESTAPIServer) handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	// YAML을 JSON으로 변환 (간단한 구현)
	// 프로덕션에서는 gopkg.in/yaml.v3 사용 권장
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	
	// 간단한 JSON 응답 (실제로는 YAML을 JSON으로 변환해야 함)
	jsonSpec := `{
  "openapi": "3.0.3",
  "info": {
    "title": "KMIP REST API",
    "version": "1.0.0",
    "description": "KMIP (Key Management Interoperability Protocol) REST API Server"
  },
  "servers": [
    {
      "url": "http://localhost:9090",
      "description": "Development server"
    }
  ],
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {
          "200": {
            "description": "Server is healthy"
          }
        }
      }
    }
  }
}`
	
	w.Write([]byte(jsonSpec))
}

// handleRedoc은 ReDoc UI 페이지를 제공
func (api *RESTAPIServer) handleRedoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(RedocHTML))
}
