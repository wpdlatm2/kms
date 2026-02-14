# Additional KMIP Operations Guide

KMIP 서버에 추가된 고급 키 관리 작업에 대한 가이드입니다.

## 📋 추가된 작업

| 작업 | 코드 | 설명 |
|------|------|------|
| Register | 0x00000003 | 외부에서 생성된 키 등록 |
| Locate | 0x00000008 | 속성으로 키 검색 |
| GetAttributes | 0x0000000B | 키 속성 조회 |
| AddAttribute | 0x0000000D | 키 속성 추가 |
| ModifyAttribute | 0x0000000E | 키 속성 수정 |
| DeleteAttribute | 0x0000000F | 키 속성 삭제 |
| Rekey | 0x00000004 | 기존 키 재생성 |

## 🔧 작업별 상세 설명

### 1. Register (키 등록)

외부에서 생성된 키를 KMIP 서버에 등록합니다.

#### 사용 사례
- 다른 시스템에서 생성된 키 가져오기
- 백업에서 키 복원
- 레거시 시스템 마이그레이션

#### REST API

```bash
curl -X POST http://localhost:9090/api/v1/keys/register \
  -H "Content-Type: application/json" \
  -d '{
    "key_type": "symmetric",
    "key_material": "0123456789abcdef0123456789abcdef",
    "algorithm": "AES",
    "length": 128,
    "attributes": {
      "name": "imported-key",
      "source": "external-system"
    }
  }'
```

**응답:**
```json
{
  "key_id": "abc123...",
  "key_type": "symmetric",
  "status": "registered",
  "created_at": "2024-02-10T12:00:00Z"
}
```

**Python 예제:**
```python
import requests
import secrets

# 외부 키 생성 (예: 다른 시스템에서)
external_key = secrets.token_hex(16)  # 128비트 hex

response = requests.post(
    'http://localhost:9090/api/v1/keys/register',
    json={
        'key_type': 'symmetric',
        'key_material': external_key,
        'algorithm': 'AES',
        'length': 128,
        'attributes': {
            'name': 'migrated-key',
            'original_system': 'legacy-db'
        }
    }
)

key_id = response.json()['key_id']
print(f"Registered key: {key_id}")
```

---

### 2. Locate (키 검색)

속성 기반으로 키를 검색합니다.

#### 사용 사례
- 특정 알고리즘의 모든 키 찾기
- 만료 예정 키 찾기
- 프로젝트별 키 그룹화
- **대체 이름(AlternateName)으로 키 찾기**

#### REST API - 기본 검색

```bash
# 모든 AES-256 키 찾기
curl -X POST http://localhost:9090/api/v1/keys/search \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "CryptographicAlgorithm": 3,
      "CryptographicLength": 256
    },
    "max_results": 10
  }'
```

#### REST API - AlternateName으로 검색

```bash
# 대체 이름으로 키 찾기
curl -X POST http://localhost:9090/api/v1/keys/search \
  -H "Content-Type: application/json" \
  -d '{
    "alternate_name": "my-production-key"
  }'
```

**응답:**
```json
{
  "key_ids": ["key1", "key2", "key3"],
  "total": 3
}
```

#### Python 예제 - AlternateName 사용

```python
# 1. 키 생성 시 AlternateName 추가
response = requests.post(
    'http://localhost:9090/api/v1/keys',
    json={
        'algorithm': 'AES',
        'length': 256,
        'attributes': {
            'AlternateName': ['web-app-key', 'production-db-key']
        }
    }
)
key_id = response.json()['key_id']

# 2. AlternateName으로 검색
response = requests.post(
    'http://localhost:9090/api/v1/keys/search',
    json={'alternate_name': 'web-app-key'}
)
found_keys = response.json()['key_ids']
print(f"Found keys: {found_keys}")

# 3. 여러 조건 조합
response = requests.post(
    'http://localhost:9090/api/v1/keys/search',
    json={
        'attributes': {
            'AlternateName': 'production-db-key',
            'environment': 'production',
            'project': 'database'
        }
    }
)
```

#### 대체 이름(AlternateName) 사용 가이드

**왜 AlternateName을 사용하나요?**
- 사람이 읽기 쉬운 이름 제공
- 여러 애플리케이션에서 동일한 키 참조
- 키 ID 변경 시에도 일관된 참조 유지

**AlternateName 형식:**
```json
{
  "AlternateName": [
    "primary-app-key",
    "backup-key-prod",
    "arn:aws:kms:us-east-1:123456789012:key/abc123"
  ]
}
```

**검색 예제:**
```python
# 특정 프로젝트의 키 검색
response = requests.post(
    'http://localhost:9090/api/v1/keys/search',
    json={
        'attributes': {
            'project': 'web-app',
            'environment': 'production'
        },
        'max_results': 50
    }
)

keys = response.json()['key_ids']
print(f"Found {len(keys)} keys for web-app production")

# 각 키에 대해 작업 수행
for key_id in keys:
    # 키 정보 조회
    key_info = requests.get(f'http://localhost:9090/api/v1/keys/{key_id}')
    print(f"Key: {key_info.json()}")
```

---

### 3. GetAttributes (속성 조회)

키의 메타데이터 속성을 조회합니다.

#### REST API

```bash
curl http://localhost:9090/api/v1/keys/attributes/{key-id}
```

**응답:**
```json
{
  "key_id": "abc123...",
  "attributes": {
    "name": "production-db-key",
    "project": "database",
    "created_by": "admin",
    "created_at": "2024-01-01T00:00:00Z",
    "expires_at": "2025-01-01T00:00:00Z"
  }
}
```

**Python 예제:**
```python
response = requests.get(
    f'http://localhost:9090/api/v1/keys/attributes/{key_id}'
)

attrs = response.json()['attributes']
print(f"Key name: {attrs.get('name')}")
print(f"Created by: {attrs.get('created_by')}")
print(f"Expires: {attrs.get('expires_at')}")
```

---

### 4. AddAttribute (속성 추가)

키에 새로운 속성을 추가합니다.

#### 사용 사례
- 키에 태그 추가
- 메타데이터 보강
- 감사 정보 추가

#### REST API

```bash
curl -X POST http://localhost:9090/api/v1/keys/attributes/{key-id} \
  -H "Content-Type: application/json" \
  -d '{
    "action": "add",
    "attributes": {
      "department": "engineering",
      "cost_center": "CC-1234",
      "compliance": "PCI-DSS"
    }
  }'
```

**Python 예제:**
```python
# 키에 태그 추가
requests.post(
    f'http://localhost:9090/api/v1/keys/attributes/{key_id}',
    json={
        'action': 'add',
        'attributes': {
            'tags': ['production', 'critical', 'encrypted'],
            'owner': 'security-team',
            'backup_required': True
        }
    }
)
```

---

### 5. ModifyAttribute (속성 수정)

기존 속성을 수정합니다.

#### REST API

```bash
curl -X POST http://localhost:9090/api/v1/keys/attributes/{key-id} \
  -H "Content-Type: application/json" \
  -d '{
    "action": "modify",
    "attributes": {
      "status": "active",
      "last_rotated": "2024-02-10T12:00:00Z"
    }
  }'
```

**Python 예제:**
```python
# 키 상태 업데이트
requests.post(
    f'http://localhost:9090/api/v1/keys/attributes/{key_id}',
    json={
        'action': 'modify',
        'attributes': {
            'status': 'deprecated',
            'replacement_key_id': new_key_id,
            'deprecated_at': datetime.now().isoformat()
        }
    }
)
```

---

### 6. DeleteAttribute (속성 삭제)

키에서 속성을 제거합니다.

#### REST API

```bash
curl -X DELETE http://localhost:9090/api/v1/keys/attributes/{key-id} \
  -H "Content-Type: application/json" \
  -d '{
    "attribute_name": "temporary_flag"
  }'
```

**Python 예제:**
```python
# 임시 속성 제거
requests.delete(
    f'http://localhost:9090/api/v1/keys/attributes/{key_id}',
    json={'attribute_name': 'temporary_flag'}
)
```

---

### 7. Rekey (키 재생성)

기존 키와 동일한 속성으로 새로운 키를 생성합니다.

#### 사용 사례
- 정기적인 키 로테이션
- 보안 사고 대응
- 규정 준수 (키 수명 관리)

#### REST API

```bash
curl -X POST http://localhost:9090/api/v1/keys/rekey/{old-key-id} \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "rotation_reason": "scheduled",
      "rotated_from": "old-key-id"
    }
  }'
```

**응답:**
```json
{
  "old_key_id": "key123...",
  "new_key_id": "key456...",
  "status": "rekeyed",
  "created_at": "2024-02-10T12:00:00Z"
}
```

**Python 예제:**
```python
# 키 로테이션
response = requests.post(
    f'http://localhost:9090/api/v1/keys/rekey/{old_key_id}',
    json={
        'attributes': {
            'rotation_reason': 'quarterly-rotation',
            'rotated_by': 'automated-script',
            'previous_key': old_key_id
        }
    }
)

new_key_id = response.json()['new_key_id']
print(f"Key rotated: {old_key_id} -> {new_key_id}")

# 애플리케이션 설정 업데이트
update_app_config(new_key_id)

# 이전 키는 일정 기간 후 삭제
schedule_key_deletion(old_key_id, days=30)
```

---

## 🔄 실전 워크플로우

### 워크플로우 1: 키 마이그레이션

```python
import requests

# 1. 외부 시스템에서 모든 키 가져오기
legacy_keys = get_keys_from_legacy_system()

# 2. 각 키를 KMIP 서버에 등록
for legacy_key in legacy_keys:
    response = requests.post(
        'http://localhost:9090/api/v1/keys/register',
        json={
            'key_type': 'symmetric',
            'key_material': legacy_key['material'],
            'algorithm': legacy_key['algorithm'],
            'length': legacy_key['length'],
            'attributes': {
                'source': 'legacy-migration',
                'original_id': legacy_key['id'],
                'migrated_at': datetime.now().isoformat()
            }
        }
    )
    print(f"Migrated: {legacy_key['id']} -> {response.json()['key_id']}")
```

### 워크플로우 2: 정기 키 로테이션

```python
import requests
from datetime import datetime, timedelta

def rotate_old_keys():
    # 1. 90일 이상 된 키 찾기
    ninety_days_ago = (datetime.now() - timedelta(days=90)).isoformat()
    
    response = requests.post(
        'http://localhost:9090/api/v1/keys/search',
        json={
            'attributes': {
                'status': 'active',
                'requires_rotation': True
            }
        }
    )
    
    old_keys = response.json()['key_ids']
    
    # 2. 각 키 로테이션
    for old_key_id in old_keys:
        # 속성 조회
        attrs_resp = requests.get(
            f'http://localhost:9090/api/v1/keys/attributes/{old_key_id}'
        )
        attrs = attrs_resp.json()['attributes']
        
        # 새 키 생성
        rekey_resp = requests.post(
            f'http://localhost:9090/api/v1/keys/rekey/{old_key_id}',
            json={
                'attributes': {
                    'rotation_date': datetime.now().isoformat(),
                    'rotation_reason': 'scheduled-90-day',
                    'previous_key': old_key_id
                }
            }
        )
        
        new_key_id = rekey_resp.json()['new_key_id']
        
        # 애플리케이션에 알림
        notify_applications(old_key_id, new_key_id)
        
        # 이전 키 상태 변경
        requests.post(
            f'http://localhost:9090/api/v1/keys/attributes/{old_key_id}',
            json={
                'action': 'modify',
                'attributes': {
                    'status': 'deprecated',
                    'replacement_key': new_key_id,
                    'deprecated_at': datetime.now().isoformat()
                }
            }
        )
        
        print(f"Rotated: {old_key_id} -> {new_key_id}")
```

### 워크플로우 3: 키 라이프사이클 관리

```python
class KeyLifecycleManager:
    def __init__(self, base_url):
        self.base_url = base_url
    
    def create_with_metadata(self, algo, length, metadata):
        """메타데이터와 함께 키 생성"""
        # 키 생성
        resp = requests.post(
            f'{self.base_url}/api/v1/keys',
            json={'algorithm': algo, 'length': length}
        )
        key_id = resp.json()['key_id']
        
        # 메타데이터 추가
        requests.post(
            f'{self.base_url}/api/v1/keys/attributes/{key_id}',
            json={'action': 'add', 'attributes': metadata}
        )
        
        return key_id
    
    def find_expiring_keys(self, days=30):
        """만료 예정 키 찾기"""
        expiry_date = (datetime.now() + timedelta(days=days)).isoformat()
        
        # 모든 키 조회 (실제로는 서버 측 필터링 필요)
        resp = requests.get(f'{self.base_url}/api/v1/keys')
        all_keys = resp.json()['keys']
        
        expiring = []
        for key in all_keys:
            attrs_resp = requests.get(
                f'{self.base_url}/api/v1/keys/attributes/{key["key_id"]}'
            )
            attrs = attrs_resp.json()['attributes']
            
            if 'expires_at' in attrs and attrs['expires_at'] <= expiry_date:
                expiring.append(key['key_id'])
        
        return expiring
    
    def archive_key(self, key_id):
        """키 아카이브"""
        requests.post(
            f'{self.base_url}/api/v1/keys/attributes/{key_id}',
            json={
                'action': 'modify',
                'attributes': {
                    'status': 'archived',
                    'archived_at': datetime.now().isoformat()
                }
            }
        )

# 사용 예제
manager = KeyLifecycleManager('http://localhost:9090')

# 메타데이터와 함께 키 생성
key_id = manager.create_with_metadata(
    'AES', 256,
    {
        'project': 'web-app',
        'environment': 'prod',
        'owner': 'security-team',
        'expires_at': (datetime.now() + timedelta(days=365)).isoformat()
    }
)

# 만료 예정 키 확인
expiring = manager.find_expiring_keys(days=30)
print(f"Keys expiring in 30 days: {expiring}")
```

---

## 📊 속성 스키마 예제

### 권장 속성 구조

```json
{
  "name": "production-db-key",
  "description": "Database encryption key for production",
  
  "classification": {
    "environment": "production",
    "project": "ecommerce",
    "department": "engineering",
    "cost_center": "CC-1234"
  },
  
  "lifecycle": {
    "status": "active",
    "created_at": "2024-01-01T00:00:00Z",
    "created_by": "admin@company.com",
    "expires_at": "2025-01-01T00:00:00Z",
    "rotation_period_days": 90
  },
  
  "compliance": {
    "pci_dss": true,
    "gdpr": true,
    "hipaa": false,
    "audit_required": true
  },
  
  "usage": {
    "purpose": "database-encryption",
    "applications": ["api-server", "batch-processor"],
    "last_used": "2024-02-10T11:30:00Z"
  },
  
  "backup": {
    "backup_required": true,
    "backup_location": "s3://backup-bucket/keys/",
    "last_backup": "2024-02-10T00:00:00Z"
  }
}
```

---

## 🔒 보안 고려사항

### 1. 속성 기반 접근 제어
```python
# 속성으로 권한 관리
def check_key_access(user, key_id):
    attrs = get_key_attributes(key_id)
    
    # 부서 확인
    if attrs.get('department') != user.department:
        raise PermissionError("Access denied")
    
    # 환경 확인
    if attrs.get('environment') == 'production' and not user.is_admin:
        raise PermissionError("Production access restricted")
```

### 2. 감사 로그
```python
# 모든 속성 변경 로깅
def modify_attribute_with_audit(key_id, changes, user):
    # 변경 전 속성 저장
    old_attrs = get_key_attributes(key_id)
    
    # 속성 수정
    modify_attributes(key_id, changes)
    
    # 감사 로그
    audit_log.write({
        'timestamp': datetime.now(),
        'user': user,
        'action': 'modify_attribute',
        'key_id': key_id,
        'old_values': old_attrs,
        'new_values': changes
    })
```

---

## 📈 성능 최적화

### 인덱싱 권장사항
자주 검색하는 속성에 대한 인덱스 생성:
- `environment`
- `project`
- `status`
- `expires_at`

### 배치 작업
```python
# 여러 키의 속성을 한번에 업데이트
def batch_update_attributes(key_ids, attributes):
    for key_id in key_ids:
        requests.post(
            f'http://localhost:9090/api/v1/keys/attributes/{key_id}',
            json={'action': 'modify', 'attributes': attributes}
        )
```

---

## 🎯 베스트 프랙티스

1. **일관된 속성 네이밍**: 조직 전체에서 동일한 속성 이름 사용
2. **필수 속성 정의**: 모든 키에 필수 속성 설정 (owner, environment 등)
3. **정기 감사**: 만료 예정 키, 미사용 키 정기 확인
4. **자동화**: 키 로테이션, 만료 알림 자동화
5. **문서화**: 속성 스키마와 사용 규칙 문서화

---

## 🔗 관련 문서

- [REST API 전체 문서](REST_API.md)
- [테스트 가이드](TESTING_GUIDE.md)
- [보안 가이드](README.md)
