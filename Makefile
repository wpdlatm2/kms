.PHONY: build clean test certs run help

# 기본 변수
BINARY_SERVER=kmip-server
BINARY_CLIENT=kmip-client
BINARY_REST_CLIENT=kmip-rest-client
BINARY_TEST_CLIENT=kmip-test-client
BINARY_REST_TEST=kmip-rest-test
GO=go

# Raft 클러스터 명령

cluster-start-quorum: build certs ## Quorum 모드로 3노드 클러스터 시작
	@./scripts/start_cluster.sh quorum

cluster-start-sync: build certs ## Sync 모드로 3노드 클러스터 시작
	@./scripts/start_cluster.sh sync

cluster-start-async: build certs ## Async 모드로 3노드 클러스터 시작
	@./scripts/start_cluster.sh async

cluster-start: cluster-start-quorum ## 기본 클러스터 시작 (quorum)

cluster-stop: ## 클러스터 중지
	@./scripts/stop_cluster.sh

cluster-test: ## 클러스터 복제 테스트
	@./scripts/test_replication.sh

cluster-logs: ## 클러스터 로그 확인
	@tail -f ./data/node-*/server.log

cluster-status: ## 클러스터 상태 확인
	@echo "=== Cluster Status ==="
	@echo ""
	@echo "Leader:"
	@curl -s http://localhost:8080/leader || echo "Failed"
	@echo ""
	@echo "Members:"
	@curl -s http://localhost:8080/stats || echo "Failed"
	@echo ""

cluster-clean: cluster-stop ## 클러스터 정리
	@rm -rf ./data/node-1 ./data/node-2 ./data/node-3
	@echo "Cluster data cleaned"

help: ## 도움말 표시
	@echo "KMIP Server - Make Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## 서버와 클라이언트 빌드
	@echo "Building KMIP server..."
	$(GO) build -o $(BINARY_SERVER) ./cmd/kmip-server
	@echo "Building KMIP client..."
	$(GO) build -o $(BINARY_CLIENT) ./cmd/kmip-client
	@echo "Building REST API client..."
	$(GO) build -o $(BINARY_REST_CLIENT) ./cmd/kmip-rest-client
	@echo "Building KMIP test client..."
	$(GO) build -o $(BINARY_TEST_CLIENT) ./cmd/kmip-test-client
	@echo "Building REST API test suite..."
	$(GO) build -o $(BINARY_REST_TEST) ./cmd/kmip-rest-test
	@echo "Build complete!"

build-server: ## 서버만 빌드
	@echo "Building KMIP server..."
	$(GO) build -o $(BINARY_SERVER) ./cmd/kmip-server

build-client: ## 클라이언트만 빌드
	@echo "Building KMIP client..."
	$(GO) build -o $(BINARY_CLIENT) ./cmd/kmip-client

clean: ## 빌드 파일 정리
	@echo "Cleaning..."
	rm -f $(BINARY_SERVER) $(BINARY_CLIENT) $(BINARY_REST_CLIENT) $(BINARY_TEST_CLIENT) $(BINARY_REST_TEST)
	rm -f *.crt *.key *.csr
	rm -rf ./data
	rm -f *.log
	rm -f test-results.json
	@echo "Clean complete!"

test: ## 테스트 실행
	@echo "Running tests..."
	$(GO) test -v ./kmip/...

fmt: ## 코드 포맷팅
	@echo "Formatting code..."
	$(GO) fmt ./...

vet: ## 정적 분석
	@echo "Running go vet..."
	$(GO) vet ./...

certs: ## 테스트용 인증서 생성
	@echo "Generating test certificates..."
	@chmod +x scripts/generate_certs.sh
	@./scripts/generate_certs.sh

run: build certs ## 빌드, 인증서 생성 후 서버 실행 (인메모리)
	@echo "Starting KMIP server with in-memory storage..."
	./$(BINARY_SERVER) -cert server.crt -key server.key

run-raft: build certs ## Raft 단일 노드로 서버 실행
	@echo "Starting KMIP server with Raft storage..."
	./$(BINARY_SERVER) -use-raft -bootstrap -cert server.crt -key server.key

run-cluster: build certs ## 3노드 Raft 클러스터 실행
	@echo "Starting 3-node Raft cluster..."
	@mkdir -p ./data/node1 ./data/node2 ./data/node3
	@echo "Starting node1 (leader)..."
	@./$(BINARY_SERVER) -use-raft -bootstrap -node-id node1 -raft-addr 127.0.0.1:7000 -data-dir ./data/node1 -addr :5696 -http-addr :8080 -cert server.crt -key server.key > node1.log 2>&1 &
	@sleep 2
	@echo "Starting node2..."
	@./$(BINARY_SERVER) -use-raft -node-id node2 -raft-addr 127.0.0.1:7001 -data-dir ./data/node2 -addr :5697 -http-addr :8081 -cert server.crt -key server.key > node2.log 2>&1 &
	@sleep 1
	@echo "Starting node3..."
	@./$(BINARY_SERVER) -use-raft -node-id node3 -raft-addr 127.0.0.1:7002 -data-dir ./data/node3 -addr :5698 -http-addr :8082 -cert server.crt -key server.key > node3.log 2>&1 &
	@sleep 2
	@echo "Joining node2 to cluster..."
	@curl -X POST http://localhost:8080/cluster/join -H "Content-Type: application/json" -d '{"node_id": "node2", "addr": "127.0.0.1:7001"}' 2>/dev/null
	@sleep 1
	@echo "Joining node3 to cluster..."
	@curl -X POST http://localhost:8080/cluster/join -H "Content-Type: application/json" -d '{"node_id": "node3", "addr": "127.0.0.1:7002"}' 2>/dev/null
	@echo ""
	@echo "Cluster started! Check status:"
	@echo "  curl http://localhost:8080/cluster/status"
	@echo ""
	@echo "Logs: node1.log, node2.log, node3.log"

stop-cluster: ## Raft 클러스터 중지
	@echo "Stopping Raft cluster..."
	@pkill -f "kmip-server" || true
	@echo "Cluster stopped"

cluster-status: ## 클러스터 상태 확인
	@echo "Checking cluster status..."
	@for port in 8080 8081 8082; do \
		echo ""; \
		echo "Node on port $$port:"; \
		curl -s http://localhost:$$port/cluster/status 2>/dev/null || echo "Node not responding"; \
	done

cluster-stats: ## Raft 통계 확인
	@echo "Raft statistics (leader node):"
	@curl -s http://localhost:8080/cluster/stats 2>/dev/null | jq '.' || echo "Failed to get stats"

run-with-client-auth: build certs ## 클라이언트 인증 활성화하여 서버 실행
	@echo "Starting KMIP server with client authentication..."
	./$(BINARY_SERVER) -cert server.crt -key server.key -ca ca.crt

test-query: build-client ## Query 테스트
	@echo "Testing Query operation..."
	./$(BINARY_CLIENT) -op query

test-discover: build-client ## DiscoverVersions 테스트
	@echo "Testing DiscoverVersions operation..."
	./$(BINARY_CLIENT) -op discover

test-create: build-client ## Create 테스트
	@echo "Testing Create operation..."
	./$(BINARY_CLIENT) -op create

all: clean build certs ## 전체 빌드 (정리 + 빌드 + 인증서)
	@echo "All tasks complete!"

deps: ## 의존성 다운로드
	@echo "Downloading dependencies..."
	$(GO) mod download
	@echo "Dependencies downloaded!"

# REST API 명령

run-rest: build certs ## REST API 서버 실행 (인메모리)
	@echo "Starting KMIP server with REST API..."
	./$(BINARY_SERVER) -cert server.crt -key server.key -enable-rest -rest-addr :9090

run-rest-raft: build certs ## REST API 서버 실행 (Raft)
	@echo "Starting KMIP server with REST API and Raft..."
	./$(BINARY_SERVER) -use-raft -bootstrap -cert server.crt -key server.key -enable-rest -rest-addr :9090

test-rest-create: ## REST API로 키 생성 테스트
	@echo "Testing REST API - Create Key..."
	./kmip-rest-client -op create -type symmetric -algo AES -length 256

test-rest-list: ## REST API로 키 목록 조회 테스트
	@echo "Testing REST API - List Keys..."
	./kmip-rest-client -op list

test-rest-info: ## REST API로 서버 정보 조회 테스트
	@echo "Testing REST API - Server Info..."
	./kmip-rest-client -op info

test-rest-versions: ## REST API로 버전 조회 테스트
	@echo "Testing REST API - Supported Versions..."
	./kmip-rest-client -op versions

test-rest-all: test-rest-info test-rest-versions test-rest-create test-rest-list ## 모든 REST API 테스트 실행
	@echo "All REST API tests completed!"

# 포괄적 테스트

test-suite-rest: build ## REST API 전체 테스트 스위트 실행
	@echo "Running REST API comprehensive test suite..."
	./$(BINARY_REST_TEST) -verbose

test-suite-rest-save: build ## REST API 테스트 결과 저장
	@echo "Running REST API test suite with results saved..."
	./$(BINARY_REST_TEST) -verbose -output test-results.json
	@echo "Results saved to test-results.json"

test-suite-rest-category: build ## REST API 카테고리별 테스트
	@echo "Testing basic operations..."
	./$(BINARY_REST_TEST) -category basic
	@echo ""
	@echo "Testing symmetric keys..."
	./$(BINARY_REST_TEST) -category symmetric
	@echo ""
	@echo "Testing asymmetric keys..."
	./$(BINARY_REST_TEST) -category asymmetric
	@echo ""
	@echo "Testing management..."
	./$(BINARY_REST_TEST) -category management

test-kmip-versions: build certs ## KMIP 버전별 테스트
	@echo "Running KMIP version compatibility tests..."
	./$(BINARY_TEST_CLIENT) -version all -verbose

test-kmip-version: build certs ## 특정 KMIP 버전 테스트 (VERSION=1.0)
	@echo "Running KMIP $(VERSION) tests..."
	./$(BINARY_TEST_CLIENT) -version $(VERSION) -verbose
