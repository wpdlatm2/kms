#!/bin/bash
# 서울-부산 클러스터 간 복제 설정 스크립트

set -e

echo "========================================="
echo "Cross-Cluster Replication Setup"
echo "Seoul ↔ Busan"
echo "========================================="
echo ""

# 색상
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# 엔드포인트
SEOUL_ENDPOINT="http://localhost:19090"
BUSAN_ENDPOINT="http://localhost:29090"

# API 키 생성 (실제로는 보안 키 사용)
API_KEY="cross-cluster-secret-key-$(date +%s)"

echo -e "${BLUE}API Key: ${API_KEY}${NC}"
echo ""

# 클러스터 상태 확인
check_cluster() {
    local name=$1
    local endpoint=$2
    
    echo -e "${YELLOW}Checking ${name} cluster...${NC}"
    
    if curl -s -f "${endpoint}/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} ${name} cluster is healthy"
        return 0
    else
        echo -e "  ${RED}✗${NC} ${name} cluster is not responding"
        return 1
    fi
}

# 원격 클러스터 등록
register_remote_cluster() {
    local local_name=$1
    local local_endpoint=$2
    local remote_id=$3
    local remote_name=$4
    local remote_endpoint=$5
    local bidirectional=$6
    
    echo -e "${YELLOW}Registering ${remote_name} on ${local_name}...${NC}"
    
    response=$(curl -s -X POST "${local_endpoint}/api/v1/replication/clusters" \
        -H "Content-Type: application/json" \
        -d "{
            \"id\": \"${remote_id}\",
            \"name\": \"${remote_name}\",
            \"endpoints\": [\"${remote_endpoint}\"],
            \"enabled\": true,
            \"priority\": 1,
            \"bidirectional\": ${bidirectional},
            \"api_key\": \"${API_KEY}\",
            \"tls_enabled\": false
        }")
    
    if echo "$response" | grep -q "success"; then
        echo -e "  ${GREEN}✓${NC} Registered ${remote_name}"
    else
        echo -e "  ${RED}✗${NC} Failed to register ${remote_name}"
        echo "     Response: $response"
    fi
}

# 복제 상태 확인
check_replication_status() {
    local name=$1
    local endpoint=$2
    
    echo -e "${YELLOW}Checking replication status for ${name}...${NC}"
    
    status=$(curl -s "${endpoint}/api/v1/replication/status")
    
    if [ ! -z "$status" ]; then
        echo "$status" | jq '.' 2>/dev/null || echo "$status"
    else
        echo -e "  ${RED}✗${NC} Failed to get status"
    fi
}

# 메인 실행
main() {
    echo -e "${BLUE}Step 1: Checking cluster health${NC}"
    echo ""
    
    check_cluster "Seoul" "$SEOUL_ENDPOINT" || {
        echo -e "${RED}Seoul cluster is not ready. Please start it first.${NC}"
        exit 1
    }
    
    check_cluster "Busan" "$BUSAN_ENDPOINT" || {
        echo -e "${RED}Busan cluster is not ready. Please start it first.${NC}"
        exit 1
    }
    
    echo ""
    echo -e "${BLUE}Step 2: Setting up bidirectional replication${NC}"
    echo ""
    
    # 서울 -> 부산 등록
    register_remote_cluster \
        "Seoul" "$SEOUL_ENDPOINT" \
        "cluster-busan" "Busan Cluster" "$BUSAN_ENDPOINT" \
        "true"
    
    sleep 2
    
    # 부산 -> 서울 등록
    register_remote_cluster \
        "Busan" "$BUSAN_ENDPOINT" \
        "cluster-seoul" "Seoul Cluster" "$SEOUL_ENDPOINT" \
        "true"
    
    echo ""
    echo -e "${BLUE}Step 3: Verifying replication status${NC}"
    echo ""
    
    sleep 3
    
    echo -e "${YELLOW}Seoul Cluster:${NC}"
    check_replication_status "Seoul" "$SEOUL_ENDPOINT"
    echo ""
    
    echo -e "${YELLOW}Busan Cluster:${NC}"
    check_replication_status "Busan" "$BUSAN_ENDPOINT"
    echo ""
    
    echo "========================================="
    echo -e "${GREEN}Cross-Cluster Replication Setup Complete!${NC}"
    echo "========================================="
    echo ""
    echo "Test replication:"
    echo ""
    echo "  # Create key in Seoul"
    echo "  curl -X POST ${SEOUL_ENDPOINT}/api/v1/keys \\"
    echo "    -d '{\"algorithm\":\"AES\",\"length\":256}'"
    echo ""
    echo "  # Wait for replication (5 seconds)"
    echo "  sleep 5"
    echo ""
    echo "  # Check in Busan"
    echo "  curl ${BUSAN_ENDPOINT}/api/v1/keys"
    echo ""
    echo "Monitor replication:"
    echo "  curl ${SEOUL_ENDPOINT}/api/v1/replication/status | jq"
    echo "  curl ${BUSAN_ENDPOINT}/api/v1/replication/status | jq"
    echo ""
}

# jq 설치 확인
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Warning: 'jq' not found. Install it for better JSON formatting.${NC}"
    echo ""
fi

main
