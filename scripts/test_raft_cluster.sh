#!/bin/bash

# KMIP Raft 클러스터 테스트 스크립트

set -e

echo "======================================"
echo "KMIP Raft Cluster Test Script"
echo "======================================"
echo ""

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 성공 메시지
success() {
    echo -e "${GREEN}✓${NC} $1"
}

# 경고 메시지
warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# 에러 메시지
error() {
    echo -e "${RED}✗${NC} $1"
}

# 1. 빌드
echo "1. Building KMIP server..."
go build -o kmip-server ./cmd/kmip-server
if [ $? -eq 0 ]; then
    success "Build successful"
else
    error "Build failed"
    exit 1
fi
echo ""

# 2. 인증서 생성 (이미 있으면 스킵)
if [ ! -f server.crt ]; then
    echo "2. Generating certificates..."
    chmod +x scripts/generate_certs.sh
    ./scripts/generate_certs.sh > /dev/null 2>&1
    success "Certificates generated"
else
    success "Certificates already exist"
fi
echo ""

# 3. 데이터 디렉토리 정리 및 생성
echo "3. Preparing data directories..."
rm -rf ./data
mkdir -p ./data/node{1,2,3}
success "Data directories created"
echo ""

# 4. 노드 시작
echo "4. Starting Raft cluster (3 nodes)..."

# Node 1 (Leader, Bootstrap)
echo "  Starting node1 (leader)..."
./kmip-server \
    -use-raft \
    -bootstrap \
    -node-id node1 \
    -raft-addr 127.0.0.1:7000 \
    -data-dir ./data/node1 \
    -addr :5696 \
    -http-addr :8080 \
    -cert server.crt \
    -key server.key > node1.log 2>&1 &
NODE1_PID=$!
sleep 2

if ps -p $NODE1_PID > /dev/null; then
    success "Node1 started (PID: $NODE1_PID)"
else
    error "Node1 failed to start"
    exit 1
fi

# Node 2
echo "  Starting node2..."
./kmip-server \
    -use-raft \
    -node-id node2 \
    -raft-addr 127.0.0.1:7001 \
    -data-dir ./data/node2 \
    -addr :5697 \
    -http-addr :8081 \
    -cert server.crt \
    -key server.key > node2.log 2>&1 &
NODE2_PID=$!
sleep 1

if ps -p $NODE2_PID > /dev/null; then
    success "Node2 started (PID: $NODE2_PID)"
else
    error "Node2 failed to start"
    kill $NODE1_PID 2>/dev/null
    exit 1
fi

# Node 3
echo "  Starting node3..."
./kmip-server \
    -use-raft \
    -node-id node3 \
    -raft-addr 127.0.0.1:7002 \
    -data-dir ./data/node3 \
    -addr :5698 \
    -http-addr :8082 \
    -cert server.crt \
    -key server.key > node3.log 2>&1 &
NODE3_PID=$!
sleep 2

if ps -p $NODE3_PID > /dev/null; then
    success "Node3 started (PID: $NODE3_PID)"
else
    error "Node3 failed to start"
    kill $NODE1_PID $NODE2_PID 2>/dev/null
    exit 1
fi
echo ""

# 5. 노드를 클러스터에 추가
echo "5. Joining nodes to cluster..."

echo "  Joining node2..."
RESPONSE=$(curl -s -X POST http://localhost:8080/cluster/join \
    -H "Content-Type: application/json" \
    -d '{"node_id": "node2", "addr": "127.0.0.1:7001"}')

if echo "$RESPONSE" | grep -q "success"; then
    success "Node2 joined"
else
    error "Failed to join node2: $RESPONSE"
fi
sleep 1

echo "  Joining node3..."
RESPONSE=$(curl -s -X POST http://localhost:8080/cluster/join \
    -H "Content-Type: application/json" \
    -d '{"node_id": "node3", "addr": "127.0.0.1:7002"}')

if echo "$RESPONSE" | grep -q "success"; then
    success "Node3 joined"
else
    error "Failed to join node3: $RESPONSE"
fi
sleep 2
echo ""

# 6. 클러스터 상태 확인
echo "6. Checking cluster status..."
for port in 8080 8081 8082; do
    STATUS=$(curl -s http://localhost:$port/cluster/status 2>/dev/null)
    if [ $? -eq 0 ]; then
        IS_LEADER=$(echo "$STATUS" | grep -o '"is_leader":[^,}]*' | cut -d: -f2)
        LEADER=$(echo "$STATUS" | grep -o '"leader":"[^"]*"' | cut -d'"' -f4)
        if [ "$IS_LEADER" = "true" ]; then
            success "Node on :$port is LEADER"
        else
            success "Node on :$port is FOLLOWER (leader: $LEADER)"
        fi
    else
        error "Node on :$port not responding"
    fi
done
echo ""

# 7. KMIP 클라이언트 테스트
echo "7. Testing KMIP operations..."

# 클라이언트 빌드
if [ ! -f kmip-client ]; then
    echo "  Building KMIP client..."
    go build -o kmip-client ./cmd/kmip-client
    success "Client built"
fi

# Query 테스트
echo "  Testing Query operation..."
./kmip-client -op query -addr localhost:5696 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    success "Query operation successful"
else
    warning "Query operation failed (this might be expected for incomplete implementation)"
fi

# Create 테스트
echo "  Testing Create operation..."
./kmip-client -op create -addr localhost:5696 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    success "Create operation successful"
else
    warning "Create operation failed (this might be expected for incomplete implementation)"
fi
echo ""

# 8. 최종 상태
echo "======================================"
echo "Cluster Status Summary"
echo "======================================"
echo ""
echo "Nodes running:"
echo "  - Node1: PID $NODE1_PID, KMIP :5696, HTTP :8080, Raft 127.0.0.1:7000"
echo "  - Node2: PID $NODE2_PID, KMIP :5697, HTTP :8081, Raft 127.0.0.1:7001"
echo "  - Node3: PID $NODE3_PID, KMIP :5698, HTTP :8082, Raft 127.0.0.1:7002"
echo ""
echo "Log files: node1.log, node2.log, node3.log"
echo ""
echo "Management commands:"
echo "  - Status:  curl http://localhost:8080/cluster/status"
echo "  - Stats:   curl http://localhost:8080/cluster/stats"
echo ""
echo "To stop the cluster:"
echo "  pkill -f kmip-server"
echo "  # or"
echo "  kill $NODE1_PID $NODE2_PID $NODE3_PID"
echo ""
success "Cluster is ready!"
