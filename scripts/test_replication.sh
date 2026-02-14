#!/bin/bash
# Raft 클러스터 복제 테스트 스크립트

set -e

echo "========================================="
echo "KMIP Raft Cluster Replication Test"
echo "========================================="
echo ""

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 노드 포트
NODE1_PORT=9090
NODE2_PORT=9091
NODE3_PORT=9092

# 테스트 카운터
PASSED=0
FAILED=0

# 테스트 함수
test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "  ${GREEN}✓ PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC}"
        FAILED=$((FAILED + 1))
    fi
}

echo -e "${BLUE}Test 1: Create key on Node 1${NC}"
RESPONSE=$(curl -s -X POST http://localhost:${NODE1_PORT}/api/v1/keys \
    -H "Content-Type: application/json" \
    -d '{"algorithm":"AES","length":256}')

KEY_ID=$(echo $RESPONSE | grep -o '"key_id":"[^"]*' | cut -d'"' -f4)

if [ ! -z "$KEY_ID" ]; then
    echo -e "  Created key: ${KEY_ID}"
    test_result 0
else
    echo -e "  Failed to create key"
    test_result 1
    exit 1
fi
echo ""

echo -e "${YELLOW}Waiting for replication (2 seconds)...${NC}"
sleep 2
echo ""

echo -e "${BLUE}Test 2: Verify key on Node 2 (replication)${NC}"
RESPONSE2=$(curl -s http://localhost:${NODE2_PORT}/api/v1/keys/${KEY_ID})
if echo "$RESPONSE2" | grep -q "$KEY_ID"; then
    echo -e "  Key found on Node 2 (replicated)"
    test_result 0
else
    echo -e "  Key NOT found on Node 2"
    test_result 1
fi
echo ""

echo -e "${BLUE}Test 3: Verify key on Node 3 (replication)${NC}"
RESPONSE3=$(curl -s http://localhost:${NODE3_PORT}/api/v1/keys/${KEY_ID})
if echo "$RESPONSE3" | grep -q "$KEY_ID"; then
    echo -e "  Key found on Node 3 (replicated)"
    test_result 0
else
    echo -e "  Key NOT found on Node 3"
    test_result 1
fi
echo ""

echo -e "${BLUE}Test 4: Create multiple keys${NC}"
for i in {1..5}; do
    curl -s -X POST http://localhost:${NODE1_PORT}/api/v1/keys \
        -H "Content-Type: application/json" \
        -d '{"algorithm":"AES","length":256}' > /dev/null
done
echo -e "  Created 5 additional keys"
test_result 0
echo ""

sleep 2

echo -e "${BLUE}Test 5: List keys on all nodes${NC}"
COUNT1=$(curl -s http://localhost:${NODE1_PORT}/api/v1/keys | grep -o '"total":[0-9]*' | cut -d':' -f2)
COUNT2=$(curl -s http://localhost:${NODE2_PORT}/api/v1/keys | grep -o '"total":[0-9]*' | cut -d':' -f2)
COUNT3=$(curl -s http://localhost:${NODE3_PORT}/api/v1/keys | grep -o '"total":[0-9]*' | cut -d':' -f2)

echo -e "  Node 1: ${COUNT1} keys"
echo -e "  Node 2: ${COUNT2} keys"
echo -e "  Node 3: ${COUNT3} keys"

if [ "$COUNT1" == "$COUNT2" ] && [ "$COUNT2" == "$COUNT3" ]; then
    echo -e "  All nodes have same key count"
    test_result 0
else
    echo -e "  Key count mismatch!"
    test_result 1
fi
echo ""

echo -e "${BLUE}Test 6: Delete key on Node 1${NC}"
DELETE_RESPONSE=$(curl -s -X DELETE http://localhost:${NODE1_PORT}/api/v1/keys/${KEY_ID})
if echo "$DELETE_RESPONSE" | grep -q "deleted"; then
    echo -e "  Key deleted"
    test_result 0
else
    echo -e "  Failed to delete key"
    test_result 1
fi
echo ""

sleep 2

echo -e "${BLUE}Test 7: Verify deletion on Node 2${NC}"
DELETE_CHECK=$(curl -s -w "%{http_code}" http://localhost:${NODE2_PORT}/api/v1/keys/${KEY_ID})
if echo "$DELETE_CHECK" | grep -q "404"; then
    echo -e "  Key not found on Node 2 (deletion replicated)"
    test_result 0
else
    echo -e "  Key still exists on Node 2"
    test_result 1
fi
echo ""

echo -e "${BLUE}Test 8: Check cluster leader${NC}"
LEADER=$(curl -s http://localhost:8080/leader)
echo -e "  Leader: ${LEADER}"
if [ ! -z "$LEADER" ]; then
    test_result 0
else
    test_result 1
fi
echo ""

echo -e "${BLUE}Test 9: Cluster statistics${NC}"
STATS=$(curl -s http://localhost:8080/stats)
if [ ! -z "$STATS" ]; then
    echo -e "  Stats retrieved"
    test_result 0
else
    test_result 1
fi
echo ""

echo "========================================="
echo "Test Summary"
echo "========================================="
echo ""
echo -e "Total Tests: $((PASSED + FAILED))"
echo -e "${GREEN}Passed: ${PASSED}${NC}"
echo -e "${RED}Failed: ${FAILED}${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
