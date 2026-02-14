#!/bin/bash

# KMIP REST API 예제 스크립트
# 다양한 REST API 사용 예제를 보여줍니다

set -e

BASE_URL="http://localhost:9090"

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "======================================"
echo "KMIP REST API Examples"
echo "======================================"
echo ""

# 1. Health Check
echo -e "${BLUE}1. Health Check${NC}"
curl -s $BASE_URL/health | jq
echo ""

# 2. API Root
echo -e "${BLUE}2. API Root - Available Endpoints${NC}"
curl -s $BASE_URL/ | jq
echo ""

# 3. Server Info
echo -e "${BLUE}3. Server Information${NC}"
curl -s $BASE_URL/api/v1/server/info | jq
echo ""

# 4. Supported Versions
echo -e "${BLUE}4. Supported KMIP Versions${NC}"
curl -s $BASE_URL/api/v1/server/versions | jq
echo ""

# 5. Create a Symmetric Key
echo -e "${BLUE}5. Create Symmetric Key (AES-256)${NC}"
KEY_RESPONSE=$(curl -s -X POST $BASE_URL/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "symmetric",
    "algorithm": "AES",
    "length": 256,
    "name": "test-key-1"
  }')
echo $KEY_RESPONSE | jq
KEY_ID=$(echo $KEY_RESPONSE | jq -r '.key_id')
echo -e "${GREEN}Created Key ID: $KEY_ID${NC}"
echo ""

# 6. Create Another Key
echo -e "${BLUE}6. Create Another Symmetric Key (AES-128)${NC}"
KEY_RESPONSE_2=$(curl -s -X POST $BASE_URL/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "symmetric",
    "algorithm": "AES",
    "length": 128,
    "name": "test-key-2"
  }')
echo $KEY_RESPONSE_2 | jq
KEY_ID_2=$(echo $KEY_RESPONSE_2 | jq -r '.key_id')
echo -e "${GREEN}Created Key ID: $KEY_ID_2${NC}"
echo ""

# 7. List All Keys
echo -e "${BLUE}7. List All Keys${NC}"
curl -s $BASE_URL/api/v1/keys | jq
echo ""

# 8. Get Specific Key
echo -e "${BLUE}8. Get Key Details (First Key)${NC}"
curl -s $BASE_URL/api/v1/keys/$KEY_ID | jq
echo ""

# 9. Get Another Key
echo -e "${BLUE}9. Get Key Details (Second Key)${NC}"
curl -s $BASE_URL/api/v1/keys/$KEY_ID_2 | jq
echo ""

# 10. Delete First Key
echo -e "${BLUE}10. Delete First Key${NC}"
curl -s -X DELETE $BASE_URL/api/v1/keys/$KEY_ID | jq
echo -e "${YELLOW}Deleted Key: $KEY_ID${NC}"
echo ""

# 11. List Keys After Deletion
echo -e "${BLUE}11. List Keys After Deletion${NC}"
curl -s $BASE_URL/api/v1/keys | jq
echo ""

# 12. Try to Get Deleted Key (Should Fail)
echo -e "${BLUE}12. Try to Get Deleted Key (Should Return 404)${NC}"
curl -s $BASE_URL/api/v1/keys/$KEY_ID | jq
echo ""

# 13. Delete Second Key
echo -e "${BLUE}13. Delete Second Key${NC}"
curl -s -X DELETE $BASE_URL/api/v1/keys/$KEY_ID_2 | jq
echo -e "${YELLOW}Deleted Key: $KEY_ID_2${NC}"
echo ""

# 14. List Keys (Should be Empty)
echo -e "${BLUE}14. List Keys (Should be Empty or Minimal)${NC}"
curl -s $BASE_URL/api/v1/keys | jq
echo ""

echo "======================================"
echo -e "${GREEN}All Examples Completed Successfully!${NC}"
echo "======================================"
