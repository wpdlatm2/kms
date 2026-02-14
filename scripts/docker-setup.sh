#!/bin/bash
# Docker 환경 설정 초기화 스크립트

set -e

echo "========================================="
echo "KMIP Docker Environment Setup"
echo "========================================="
echo ""

# 색상
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 클러스터 타입 선택
CLUSTER_TYPE=${1:-single}

echo -e "${BLUE}Cluster Type: ${CLUSTER_TYPE}${NC}"
echo ""

# 디렉토리 생성 함수
create_directories() {
    local cluster=$1
    local nodes=$2
    
    echo -e "${YELLOW}Creating directories for ${cluster}...${NC}"
    
    for i in $(seq 1 $nodes); do
        mkdir -p config/${cluster}/node${i}
        mkdir -p volumes/${cluster}/node${i}/data
        mkdir -p volumes/${cluster}/node${i}/logs
        echo -e "  ${GREEN}✓${NC} Created directories for ${cluster}/node${i}"
    done
}

# 설정 파일 생성 함수
create_config() {
    local cluster=$1
    local node=$2
    local node_id=$3
    local raft_addr=$4
    
    local config_file="config/${cluster}/node${node}/config.yaml"
    
    cat > ${config_file} << EOF
# KMIP Server Configuration
# Cluster: ${cluster}
# Node: ${node_id}

node:
  id: "${node_id}"
  bind_addr: "${raft_addr}"
  data_dir: "/app/data"
  bootstrap: $([ "$node" -eq 1 ] && echo "true" || echo "false")

replication:
  enabled: true
  factor: 3
  min_replicas: 2
  mode: "quorum"
  consistency: "strong"
  timeout_ms: 5000
  retry_attempts: 3
  retry_backoff_ms: 100

performance:
  heartbeat_timeout: "1s"
  election_timeout: "1s"
  commit_timeout: "50ms"
  snapshot_interval: "120s"
  snapshot_threshold: 8192

logging:
  level: "info"
  file: "/app/logs/${node_id}.log"
  max_size_mb: 100
  max_backups: 3
  max_age_days: 30
EOF

    echo -e "  ${GREEN}✓${NC} Created config for ${cluster}/node${node}"
}

# 인증서 생성
generate_certs() {
    if [ ! -d "certs" ]; then
        mkdir -p certs
    fi
    
    if [ ! -f "certs/server.crt" ]; then
        echo -e "${YELLOW}Generating TLS certificates...${NC}"
        
        # CA 생성
        openssl genrsa -out certs/ca.key 4096 2>/dev/null
        openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
            -subj "/C=KR/ST=Seoul/L=Seoul/O=KMIP/CN=KMIP-CA" 2>/dev/null
        
        # 서버 인증서 생성
        openssl genrsa -out certs/server.key 2048 2>/dev/null
        openssl req -new -key certs/server.key -out certs/server.csr \
            -subj "/C=KR/ST=Seoul/L=Seoul/O=KMIP/CN=kmip-server" 2>/dev/null
        
        # SAN 설정
        cat > certs/san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = kmip-node1
DNS.3 = kmip-node2
DNS.4 = kmip-node3
DNS.5 = seoul-node1
DNS.6 = seoul-node2
DNS.7 = seoul-node3
DNS.8 = busan-node1
DNS.9 = busan-node2
DNS.10 = busan-node3
IP.1 = 127.0.0.1
IP.2 = 172.20.0.11
IP.3 = 172.20.0.12
IP.4 = 172.20.0.13
IP.5 = 172.21.0.11
IP.6 = 172.21.0.12
IP.7 = 172.21.0.13
IP.8 = 172.22.0.11
IP.9 = 172.22.0.12
IP.10 = 172.22.0.13
EOF
        
        openssl x509 -req -days 3650 -in certs/server.csr \
            -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
            -out certs/server.crt -extensions v3_req -extfile certs/san.cnf 2>/dev/null
        
        rm certs/server.csr certs/san.cnf
        
        echo -e "  ${GREEN}✓${NC} TLS certificates generated"
    else
        echo -e "  ${GREEN}✓${NC} TLS certificates already exist"
    fi
}

# .dockerignore 생성
create_dockerignore() {
    cat > .dockerignore << EOF
# 데이터 디렉토리
volumes/
data/
logs/
*.log

# 설정 파일
config/

# Git
.git
.gitignore

# Docker
docker-compose*.yml
Dockerfile
.dockerignore

# 문서
*.md
docs/

# 테스트
*_test.go
test/

# 빌드 아티팩트
*.tar.gz
*.zip

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
EOF
    echo -e "${GREEN}✓${NC} Created .dockerignore"
}

# 메인 실행
main() {
    case $CLUSTER_TYPE in
        single)
            echo -e "${BLUE}Setting up Single Cluster (3 nodes)${NC}"
            echo ""
            
            create_directories "" 3
            
            create_config "" 1 "node-1" "172.20.0.11:7000"
            create_config "" 2 "node-2" "172.20.0.12:7000"
            create_config "" 3 "node-3" "172.20.0.13:7000"
            ;;
            
        multi)
            echo -e "${BLUE}Setting up Multi Cluster (Seoul + Busan)${NC}"
            echo ""
            
            # 서울 클러스터
            create_directories "seoul" 3
            create_config "seoul" 1 "seoul-node-1" "172.21.0.11:7000"
            create_config "seoul" 2 "seoul-node-2" "172.21.0.12:7000"
            create_config "seoul" 3 "seoul-node-3" "172.21.0.13:7000"
            
            # 부산 클러스터
            create_directories "busan" 3
            create_config "busan" 1 "busan-node-1" "172.22.0.11:7000"
            create_config "busan" 2 "busan-node-2" "172.22.0.12:7000"
            create_config "busan" 3 "busan-node-3" "172.22.0.13:7000"
            ;;
            
        *)
            echo -e "${RED}Unknown cluster type: ${CLUSTER_TYPE}${NC}"
            echo "Usage: $0 [single|multi]"
            exit 1
            ;;
    esac
    
    # 인증서 생성
    generate_certs
    
    # .dockerignore 생성
    create_dockerignore
    
    echo ""
    echo "========================================="
    echo -e "${GREEN}Setup Complete!${NC}"
    echo "========================================="
    echo ""
    
    if [ "$CLUSTER_TYPE" = "single" ]; then
        echo "Next steps:"
        echo "  1. Build image:     docker-compose build"
        echo "  2. Start cluster:   docker-compose up -d"
        echo "  3. Check status:    docker-compose ps"
        echo "  4. View logs:       docker-compose logs -f"
        echo "  5. Test:            curl http://localhost:9090/health"
        echo ""
        echo "Access points:"
        echo "  Node 1: http://localhost:9090"
        echo "  Node 2: http://localhost:9091"
        echo "  Node 3: http://localhost:9092"
    else
        echo "Next steps:"
        echo "  1. Build image:     docker-compose -f docker-compose.multi-cluster.yml build"
        echo "  2. Start clusters:  docker-compose -f docker-compose.multi-cluster.yml up -d"
        echo "  3. Check status:    docker-compose -f docker-compose.multi-cluster.yml ps"
        echo "  4. Setup replication: ./scripts/setup-cross-cluster-replication.sh"
        echo ""
        echo "Access points:"
        echo "  Seoul Cluster:"
        echo "    Node 1: http://localhost:19090"
        echo "    Node 2: http://localhost:19091"
        echo "    Node 3: http://localhost:19092"
        echo ""
        echo "  Busan Cluster:"
        echo "    Node 1: http://localhost:29090"
        echo "    Node 2: http://localhost:29091"
        echo "    Node 3: http://localhost:29092"
    fi
    echo ""
}

# 실행
main
