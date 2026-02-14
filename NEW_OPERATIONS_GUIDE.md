# 🚀 추가된 KMIP 오퍼레이션 빠른 가이드

## ✅ 구현 완료

7개의 새로운 KMIP 오퍼레이션이 추가되었습니다:

1. **Register** - 외부 키 등록
2. **Locate** - 속성으로 키 검색
3. **Locate by AlternateName** - 대체 이름으로 검색
4. **GetAttributes** - 속성 조회
5. **AddAttribute** - 속성 추가
6. **ModifyAttribute** - 속성 수정
7. **DeleteAttribute** - 속성 삭제
8. **Rekey** - 키 재생성

## 📦 빠른 시작

### 1. 압축 해제
```bash
tar -xzf kmip-server-complete.tar.gz
cd kmip-server/
```

### 2. 빌드 및 실행
```bash
make build
make run-rest
```

### 3. 포괄적 데모 실행
```bash
# Python 데모 (모든 작업 예제 포함)
python3 examples/all_operations_demo.py
```

### 4. 테스트 실행
```bash
# 전체 테스트 (새 작업 포함)
make test-suite-rest
```

## 🔧 새 작업 사용 예제

### Register (외부 키 등록)
```bash
curl -X POST http://localhost:9090/api/v1/keys/register \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "symmetric",
    "key_material": "0123456789abcdef0123456789abcdef",
    "algorithm": "AES",
    "length": 128
  }'
```

### Locate (검색)
```bash
# 속성으로 검색
curl -X POST http://localhost:9090/api/v1/keys/search \
  -H "Content-Type: application/json" \
  -d '{"attributes": {"environment": "production"}}'

# AlternateName으로 검색
curl -X POST http://localhost:9090/api/v1/keys/search \
  -H "Content-Type: application/json" \
  -d '{"alternate_name": "my-key-name"}'
```

### GetAttributes (속성 조회)
```bash
curl http://localhost:9090/api/v1/keys/attributes/{key-id}
```

### AddAttribute (속성 추가)
```bash
curl -X POST http://localhost:9090/api/v1/keys/attributes/{key-id} \
  -H "Content-Type: application/json" \
  -d '{
    "action": "add",
    "attributes": {
      "department": "engineering",
      "project": "web-app"
    }
  }'
```

### ModifyAttribute (속성 수정)
```bash
curl -X POST http://localhost:9090/api/v1/keys/attributes/{key-id} \
  -H "Content-Type: application/json" \
  -d '{
    "action": "modify",
    "attributes": {"status": "active"}
  }'
```

### DeleteAttribute (속성 삭제)
```bash
curl -X DELETE http://localhost:9090/api/v1/keys/attributes/{key-id} \
  -H "Content-Type: application/json" \
  -d '{"attribute_name": "temporary"}'
```

### Rekey (키 재생성)
```bash
curl -X POST http://localhost:9090/api/v1/keys/rekey/{key-id} \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "rotation_reason": "scheduled"
    }
  }'
```

## 📚 주요 문서

1. **ADVANCED_OPERATIONS.md** - 모든 작업 상세 가이드
2. **README.md** - 프로젝트 전체 개요
3. **TESTING_GUIDE.md** - 테스트 가이드
4. **examples/all_operations_demo.py** - Python 예제

## 🎯 테스트 커버리지

새로 추가된 자동화 테스트:
- Register Key ✅
- Locate by Attributes ✅
- Locate by AlternateName ✅
- Get Attributes ✅
- Add Attributes ✅
- Modify Attributes ✅
- Delete Attribute ✅
- Rekey ✅

**총 55개 이상의 자동화 테스트**

## 🔗 REST API 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| POST | `/api/v1/keys/register` | 외부 키 등록 |
| POST | `/api/v1/keys/search` | 키 검색 |
| GET | `/api/v1/keys/attributes/{id}` | 속성 조회 |
| POST | `/api/v1/keys/attributes/{id}` | 속성 추가/수정 |
| DELETE | `/api/v1/keys/attributes/{id}` | 속성 삭제 |
| POST | `/api/v1/keys/rekey/{id}` | 키 재생성 |

## 💡 실전 사용 사례

### 사례 1: 키 마이그레이션
```python
# 레거시 시스템에서 키 가져와서 등록
for legacy_key in old_system_keys:
    client.register_key(
        legacy_key['material'],
        attributes={'source': 'legacy'}
    )
```

### 사례 2: 정기 키 로테이션
```python
# 90일 이상 된 키 찾아서 재생성
old_keys = client.locate_keys(
    attributes={'requires_rotation': True}
)
for key_id in old_keys['key_ids']:
    new_key = client.rekey(key_id)
```

### 사례 3: 키 태깅 및 검색
```python
# 프로덕션 키에 컴플라이언스 태그 추가
prod_keys = client.locate_keys(
    attributes={'environment': 'production'}
)
for key_id in prod_keys['key_ids']:
    client.add_attributes(key_id, {
        'compliance': ['PCI-DSS', 'SOC2']
    })
```

## 🎉 완성!

모든 주요 KMIP 오퍼레이션이 구현되었습니다!
