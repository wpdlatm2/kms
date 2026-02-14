#!/bin/bash
# 3노드 Raft 클러스터 시작 스크립트

set -e

echo "========================================="
echo "KMIP Raft Cluster Startup Script"
echo "========================================="
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 설정
NODE1_RAFT_PORT=7000
NODE2_RAFT_PORT=7001
NODE3_RAFT_PORT=7002

NODE1_REST_PORT=9090
NODE2_REST_PORT=9091
NODE3_REST_PORT=9092

NODE1_KMIP_PORT=5696
NODE2_KMIP_PORT=5697
NODE3_KMIP_PORT=5698

# 복제 모드 (quorum, sync, async)
REPLICATION_MODE=${1:-quorum}

echo -e "${BLUE}Replication Mode: ${REPLICATION_MODE}${NC}"
echo ""

# 데이터 디렉토리 정리
cleanup() {
    echo -e "${YELLOW}Cleaning up data directories...${NC}"
    rm -rf ./data/node-1 ./data/node-2 ./data/node-3
    mkdir -p ./data/node-1 ./data/node-2 ./data/node-3
}

# 노드 종료
stop_nodes() {
    echo -e "${YELLOW}Stopping existing nodes...${NC}"
    pkill -f "kmip-server.*node-[123]" || true
    sleep 2
}

# 인증서 확인
check_certs() {
    if [ ! -f server.crt ] || [ ! -f server.key ]; then
        echo -e "${YELLOW}Certificates not found. Generating...${NC}"
        ./scripts/generate_certs.sh
    fi
}

# 메인 함수
main() {
    # 빌드 확인
    if [ ! -f ./kmip-server ]; then
        echo -e "${RED}Error: kmip-server binary not found${NC}"
        echo "Please run: make build"
        exit 1
    fi
    
    # 기존 노드 종료
    stop_nodes
    
    # 데이터 정리
    cleanup
    
    # 인증서 확인
    check_certs
    
    echo -e "${GREEN}Starting 3-node Raft cluster...${NC}"
    echo ""
    
    # Node 1 (리더) 시작
    echo -e "${BLUE}Starting Node 1 (Leader)...${NC}"
    ./kmip-server \
        -node-id node-1 \
        -raft-addr 127.0.0.1:${NODE1_RAFT_PORT} \
        -data-dir ./data/node-1 \
        -bootstrap \
        -use-raft \
        -replication true \
        -replication-mode ${REPLICATION_MODE} \
        -replication-factor 3 \
        -min-replicas 2 \
        -enable-rest \
        -rest-addr :${NODE1_REST_PORT} \
        -addr :${NODE1_KMIP_PORT} \
        -http-addr :8080 \
        > ./data/node-1/server.log 2>&1 &
    NODE1_PID=$!
    echo -e "  ${GREEN}✓${NC} Node 1 started (PID: $NODE1_PID)"
    echo -e "    - KMIP: :${NODE1_KMIP_PORT}"
    echo -e "    - REST: :${NODE1_REST_PORT}"
    echo -e "    - Raft: :${NODE1_RAFT_PORT}"
    echo -e "    - HTTP: :8080"
    echo ""
    
    # 리더가 준비될 때까지 대기
    echo -e "${YELLOW}Waiting for leader to be ready...${NC}"
    sleep 5
    
    # Node 2 시작
    echo -e "${BLUE}Starting Node 2 (Follower)...${NC}"
    ./kmip-server \
        -node-id node-2 \
        -raft-addr 127.0.0.1:${NODE2_RAFT_PORT} \
        -data-dir ./data/node-2 \
        -use-raft \
        -replication true \
        -replication-mode ${REPLICATION_MODE} \
        -replication-factor 3 \
        -min-replicas 2 \
        -enable-rest \
        -rest-addr :${NODE2_REST_PORT} \
        -addr :${NODE2_KMIP_PORT} \
        -http-addr :8081 \
        > ./data/node-2/server.log 2>&1 &
    NODE2_PID=$!
    echo -e "  ${GREEN}✓${NC} Node 2 started (PID: $NODE2_PID)"
    echo -e "    - KMIP: :${NODE2_KMIP_PORT}"
    echo -e "    - REST: :${NODE2_REST_PORT}"
    echo -e "    - Raft: :${NODE2_RAFT_PORT}"
    echo -e "    - HTTP: :8081"
    echo ""
    
    # Node 2를 클러스터에 추가
    sleep 2
    echo -e "${YELLOW}Adding Node 2 to cluster...${NC}"
    curl -s -X POST http://localhost:8080/join \
        -H "Content-Type: application/json" \
        -d "{\"id\":\"node-2\",\"address\":\"127.0.0.1:${NODE2_RAFT_PORT}\"}" || true
    echo ""
    
    # Node 3 시작
    echo -e "${BLUE}Starting Node 3 (Follower)...${NC}"
    ./kmip-server \
        -node-id node-3 \
        -raft-addr 127.0.0.1:${NODE3_RAFT_PORT} \
        -data-dir ./data/node-3 \
        -use-raft \
        -replication true \
        -replication-mode ${REPLICATION_MODE} \
        -replication-factor 3 \
        -min-replicas 2 \
        -enable-rest \
        -rest-addr :${NODE3_REST_PORT} \
        -addr :${NODE3_KMIP_PORT} \
        -http-addr :8082 \
        > ./data/node-3/server.log 2>&1 &
    NODE3_PID=$!
    echo -e "  ${GREEN}✓${NC} Node 3 started (PID: $NODE3_PID)"
    echo -e "    - KMIP: :${NODE3_KMIP_PORT}"
    echo -e "    - REST: :${NODE3_REST_PORT}"
    echo -e "    - Raft: :${NODE3_RAFT_PORT}"
    echo -e "    - HTTP: :8082"
    echo ""
    
    # Node 3을 클러스터에 추가
    sleep 2
    echo -e "${YELLOW}Adding Node 3 to cluster...${NC}"
    curl -s -X POST http://localhost:8080/join \
        -H "Content-Type: application/json" \
        -d "{\"id\":\"node-3\",\"address\":\"127.0.0.1:${NODE3_RAFT_PORT}\"}" || true
    echo ""
    
    # 클러스터 상태 확인
    sleep 3
    echo -e "${GREEN}Cluster started successfully!${NC}"
    echo ""
    
    echo "========================================="
    echo "Cluster Information"
    echo "========================================="
    echo ""
    echo "Replication Mode: ${REPLICATION_MODE}"
    echo "Nodes: 3"
    echo "Quorum: 2"
    echo ""
    
    echo "Node Endpoints:"
    echo "  Node 1: http://localhost:${NODE1_REST_PORT}"
    echo "  Node 2: http://localhost:${NODE2_REST_PORT}"
    echo "  Node 3: http://localhost:${NODE3_REST_PORT}"
    echo ""
    
    echo "Management API:"
    echo "  Node 1: http://localhost:8080"
    echo "  Node 2: http://localhost:8081"
    echo "  Node 3: http://localhost:8082"
    echo ""
    
    echo "Process IDs:"
    echo "  Node 1: $NODE1_PID"
    echo "  Node 2: $NODE2_PID"
    echo "  Node 3: $NODE3_PID"
    echo ""
    
    echo "Logs:"
    echo "  Node 1: tail -f ./data/node-1/server.log"
    echo "  Node 2: tail -f ./data/node-2/server.log"
    echo "  Node 3: tail -f ./data/node-3/server.log"
    echo ""
    
    echo "Test Commands:"
    echo "  # Create key on Node 1"
    echo "  curl -X POST http://localhost:${NODE1_REST_PORT}/api/v1/keys -d '{\"algorithm\":\"AES\",\"length\":256}'"
    echo ""
    echo "  # List keys on Node 2 (should see replicated key)"
    echo "  curl http://localhost:${NODE2_REST_PORT}/api/v1/keys"
    echo ""
    echo "  # Check cluster leader"
    echo "  curl http://localhost:8080/leader"
    echo ""
    
    echo "Stop Cluster:"
    echo "  ./scripts/stop_cluster.sh"
    echo ""
    
    # 로그 모니터링 옵션
    read -p "Monitor logs? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Monitoring all node logs (Ctrl+C to exit)...${NC}"
        tail -f ./data/node-*/server.log
    fi
}

# 도움말
usage() {
    echo "Usage: $0 [replication_mode]"
    echo ""
    echo "Replication Modes:"
    echo "  quorum  - Wait for majority (default, recommended)"
    echo "  sync    - Wait for all replicas (safest, slowest)"
    echo "  async   - Don't wait for replicas (fastest, data loss possible)"
    echo ""
    echo "Examples:"
    echo "  $0            # Start with quorum mode"
    echo "  $0 quorum     # Start with quorum mode"
    echo "  $0 sync       # Start with sync mode"
    echo "  $0 async      # Start with async mode"
    exit 0
}

# 인자 확인
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    usage
fi

# 메인 실행
main
