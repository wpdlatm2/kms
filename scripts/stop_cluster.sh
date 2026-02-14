#!/bin/bash
# Raft 클러스터 중지 스크립트

echo "========================================="
echo "Stopping KMIP Raft Cluster"
echo "========================================="
echo ""

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 실행 중인 노드 찾기
PIDS=$(pgrep -f "kmip-server.*node-")

if [ -z "$PIDS" ]; then
    echo -e "${YELLOW}No running nodes found${NC}"
    exit 0
fi

echo -e "${YELLOW}Found running nodes:${NC}"
for PID in $PIDS; do
    CMD=$(ps -p $PID -o args= | head -c 60)
    echo "  PID $PID: $CMD..."
done
echo ""

# 노드 종료
echo -e "${YELLOW}Stopping nodes...${NC}"
pkill -SIGTERM -f "kmip-server.*node-"

# 종료 대기
sleep 2

# 강제 종료 확인
REMAINING=$(pgrep -f "kmip-server.*node-")
if [ ! -z "$REMAINING" ]; then
    echo -e "${RED}Some processes didn't stop, forcing...${NC}"
    pkill -SIGKILL -f "kmip-server.*node-"
    sleep 1
fi

echo -e "${GREEN}✓ All nodes stopped${NC}"
echo ""

# 옵션: 데이터 정리
read -p "Remove data directories? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Removing data...${NC}"
    rm -rf ./data/node-1 ./data/node-2 ./data/node-3
    echo -e "${GREEN}✓ Data removed${NC}"
fi

echo ""
echo "Cluster stopped successfully"
