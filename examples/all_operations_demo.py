#!/usr/bin/env python3
"""
KMIP Server - Complete Operations Example
모든 KMIP 오퍼레이션을 사용하는 포괄적인 예제
"""

import requests
import json
from datetime import datetime, timedelta

BASE_URL = "http://localhost:9090"


class KMIPClient:
    """KMIP REST API 클라이언트"""
    
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
    
    # ===== 1. Create (키 생성) =====
    def create_key(self, algorithm="AES", length=256, attributes=None):
        """대칭 키 생성"""
        response = requests.post(
            f"{self.base_url}/api/v1/keys",
            json={
                "key_type": "symmetric",
                "algorithm": algorithm,
                "length": length,
                "attributes": attributes or {}
            }
        )
        return response.json()
    
    # ===== 2. CreateKeyPair (키 쌍 생성) =====
    def create_keypair(self, algorithm="RSA", length=2048, attributes=None):
        """비대칭 키 쌍 생성"""
        response = requests.post(
            f"{self.base_url}/api/v1/keypairs",
            json={
                "algorithm": algorithm,
                "length": length,
                "attributes": attributes or {}
            }
        )
        return response.json()
    
    # ===== 3. Register (키 등록) =====
    def register_key(self, key_material, algorithm="AES", length=128, attributes=None):
        """외부 키 등록"""
        response = requests.post(
            f"{self.base_url}/api/v1/keys/register",
            json={
                "key_type": "symmetric",
                "key_material": key_material,
                "algorithm": algorithm,
                "length": length,
                "attributes": attributes or {}
            }
        )
        return response.json()
    
    # ===== 4. Get (키 조회) =====
    def get_key(self, key_id):
        """키 조회"""
        response = requests.get(f"{self.base_url}/api/v1/keys/{key_id}")
        return response.json()
    
    # ===== 5. Locate (키 검색) =====
    def locate_keys(self, attributes=None, alternate_name=None, max_results=None):
        """속성으로 키 검색"""
        payload = {}
        if attributes:
            payload["attributes"] = attributes
        if alternate_name:
            payload["alternate_name"] = alternate_name
        if max_results:
            payload["max_results"] = max_results
        
        response = requests.post(
            f"{self.base_url}/api/v1/keys/search",
            json=payload
        )
        return response.json()
    
    # ===== 6. GetAttributes (속성 조회) =====
    def get_attributes(self, key_id):
        """키 속성 조회"""
        response = requests.get(
            f"{self.base_url}/api/v1/keys/attributes/{key_id}"
        )
        return response.json()
    
    # ===== 7. AddAttribute (속성 추가) =====
    def add_attributes(self, key_id, attributes):
        """키 속성 추가"""
        response = requests.post(
            f"{self.base_url}/api/v1/keys/attributes/{key_id}",
            json={"action": "add", "attributes": attributes}
        )
        return response.json()
    
    # ===== 8. ModifyAttribute (속성 수정) =====
    def modify_attributes(self, key_id, attributes):
        """키 속성 수정"""
        response = requests.post(
            f"{self.base_url}/api/v1/keys/attributes/{key_id}",
            json={"action": "modify", "attributes": attributes}
        )
        return response.json()
    
    # ===== 9. DeleteAttribute (속성 삭제) =====
    def delete_attribute(self, key_id, attribute_name):
        """키 속성 삭제"""
        response = requests.delete(
            f"{self.base_url}/api/v1/keys/attributes/{key_id}",
            json={"attribute_name": attribute_name}
        )
        return response.json()
    
    # ===== 10. Rekey (키 재생성) =====
    def rekey(self, key_id, attributes=None):
        """키 재생성"""
        response = requests.post(
            f"{self.base_url}/api/v1/keys/rekey/{key_id}",
            json={"attributes": attributes or {}}
        )
        return response.json()
    
    # ===== 11. Destroy (키 삭제) =====
    def destroy_key(self, key_id):
        """키 삭제"""
        response = requests.delete(f"{self.base_url}/api/v1/keys/{key_id}")
        return response.json()
    
    # ===== 12. Query (서버 정보) =====
    def query_server(self):
        """서버 정보 조회"""
        response = requests.get(f"{self.base_url}/api/v1/server/info")
        return response.json()


def demo_basic_operations():
    """기본 작업 데모"""
    print("\n" + "="*60)
    print("데모 1: 기본 키 생성 및 조회")
    print("="*60)
    
    client = KMIPClient()
    
    # 1. 키 생성
    print("\n[1] AES-256 키 생성...")
    key_data = client.create_key("AES", 256)
    key_id = key_data["key_id"]
    print(f"    ✓ 키 생성됨: {key_id}")
    
    # 2. 키 조회
    print("\n[2] 키 조회...")
    key_info = client.get_key(key_id)
    print(f"    ✓ 알고리즘: {key_info['algorithm']}")
    print(f"    ✓ 길이: {key_info['length']} bits")
    
    # 3. 키 삭제
    print("\n[3] 키 삭제...")
    client.destroy_key(key_id)
    print(f"    ✓ 키 삭제됨")


def demo_attributes():
    """속성 관리 데모"""
    print("\n" + "="*60)
    print("데모 2: 속성 관리")
    print("="*60)
    
    client = KMIPClient()
    
    # 1. 초기 속성과 함께 키 생성
    print("\n[1] 초기 속성과 함께 키 생성...")
    key_data = client.create_key(
        "AES", 256,
        attributes={
            "name": "production-db-key",
            "environment": "production",
            "project": "database"
        }
    )
    key_id = key_data["key_id"]
    print(f"    ✓ 키 생성됨: {key_id}")
    
    # 2. 속성 조회
    print("\n[2] 속성 조회...")
    attrs = client.get_attributes(key_id)
    print(f"    ✓ 현재 속성: {json.dumps(attrs['attributes'], indent=6)}")
    
    # 3. 속성 추가
    print("\n[3] 새 속성 추가...")
    client.add_attributes(key_id, {
        "department": "engineering",
        "owner": "security-team",
        "cost_center": "CC-1234"
    })
    print(f"    ✓ 속성 추가됨")
    
    # 4. 속성 수정
    print("\n[4] 속성 수정...")
    client.modify_attributes(key_id, {
        "status": "active",
        "last_updated": datetime.now().isoformat()
    })
    print(f"    ✓ 속성 수정됨")
    
    # 5. 업데이트된 속성 조회
    print("\n[5] 업데이트된 속성 조회...")
    attrs = client.get_attributes(key_id)
    print(f"    ✓ 업데이트된 속성:")
    for k, v in attrs['attributes'].items():
        print(f"      - {k}: {v}")
    
    # 6. 속성 삭제
    print("\n[6] 속성 삭제...")
    client.delete_attribute(key_id, "cost_center")
    print(f"    ✓ 'cost_center' 속성 삭제됨")
    
    # 정리
    client.destroy_key(key_id)


def demo_alternate_names():
    """AlternateName 검색 데모"""
    print("\n" + "="*60)
    print("데모 3: AlternateName을 이용한 키 검색")
    print("="*60)
    
    client = KMIPClient()
    
    # 1. 여러 AlternateName으로 키 생성
    print("\n[1] AlternateName과 함께 키 생성...")
    keys = []
    
    key1 = client.create_key("AES", 256, {
        "AlternateName": ["web-app-key", "prod-frontend"],
        "project": "web-app"
    })
    keys.append(key1["key_id"])
    print(f"    ✓ 키 1: {key1['key_id']} (web-app-key)")
    
    key2 = client.create_key("AES", 256, {
        "AlternateName": ["api-key", "prod-backend"],
        "project": "api-service"
    })
    keys.append(key2["key_id"])
    print(f"    ✓ 키 2: {key2['key_id']} (api-key)")
    
    key3 = client.create_key("AES", 256, {
        "AlternateName": ["db-key", "prod-database"],
        "project": "database"
    })
    keys.append(key3["key_id"])
    print(f"    ✓ 키 3: {key3['key_id']} (db-key)")
    
    # 2. AlternateName으로 검색
    print("\n[2] 'web-app-key'로 검색...")
    result = client.locate_keys(alternate_name="web-app-key")
    print(f"    ✓ 발견된 키: {result['key_ids']}")
    
    # 3. 속성으로 검색
    print("\n[3] project='database'로 검색...")
    result = client.locate_keys(attributes={"project": "database"})
    print(f"    ✓ 발견된 키: {result['key_ids']}")
    
    # 정리
    for key_id in keys:
        client.destroy_key(key_id)


def demo_key_rotation():
    """키 로테이션 데모"""
    print("\n" + "="*60)
    print("데모 4: 키 로테이션 (Rekey)")
    print("="*60)
    
    client = KMIPClient()
    
    # 1. 원본 키 생성
    print("\n[1] 원본 키 생성...")
    old_key = client.create_key("AES", 256, {
        "name": "rotation-test-key",
        "created_at": datetime.now().isoformat(),
        "status": "active"
    })
    old_key_id = old_key["key_id"]
    print(f"    ✓ 원본 키: {old_key_id}")
    
    # 2. 키 정보 확인
    print("\n[2] 원본 키 정보...")
    old_attrs = client.get_attributes(old_key_id)
    print(f"    ✓ 속성: {json.dumps(old_attrs['attributes'], indent=6)}")
    
    # 3. 키 재생성
    print("\n[3] 키 재생성...")
    rekey_result = client.rekey(old_key_id, {
        "rotation_reason": "quarterly-rotation",
        "rotated_at": datetime.now().isoformat(),
        "previous_key": old_key_id
    })
    new_key_id = rekey_result["new_key_id"]
    print(f"    ✓ 새 키: {new_key_id}")
    
    # 4. 새 키 확인
    print("\n[4] 새 키 정보...")
    new_attrs = client.get_attributes(new_key_id)
    print(f"    ✓ 속성: {json.dumps(new_attrs['attributes'], indent=6)}")
    
    # 5. 이전 키 상태 업데이트
    print("\n[5] 이전 키 상태를 'deprecated'로 변경...")
    client.modify_attributes(old_key_id, {
        "status": "deprecated",
        "replacement_key": new_key_id,
        "deprecated_at": datetime.now().isoformat()
    })
    print(f"    ✓ 이전 키 상태 업데이트됨")
    
    # 정리
    client.destroy_key(old_key_id)
    client.destroy_key(new_key_id)


def demo_register_external_key():
    """외부 키 등록 데모"""
    print("\n" + "="*60)
    print("데모 5: 외부 키 등록 (Register)")
    print("="*60)
    
    client = KMIPClient()
    
    # 1. 외부 시스템에서 생성된 키 (hex 형식)
    print("\n[1] 외부 키 등록...")
    external_key = "0123456789abcdef0123456789abcdef"
    
    key_data = client.register_key(
        external_key,
        algorithm="AES",
        length=128,
        attributes={
            "source": "legacy-system",
            "imported_at": datetime.now().isoformat(),
            "original_id": "legacy-key-001"
        }
    )
    key_id = key_data["key_id"]
    print(f"    ✓ 등록된 키: {key_id}")
    
    # 2. 등록된 키 확인
    print("\n[2] 등록된 키 정보...")
    key_info = client.get_key(key_id)
    print(f"    ✓ 알고리즘: {key_info['algorithm']}")
    print(f"    ✓ 길이: {key_info['length']} bits")
    
    attrs = client.get_attributes(key_id)
    print(f"    ✓ 속성: {json.dumps(attrs['attributes'], indent=6)}")
    
    # 정리
    client.destroy_key(key_id)


def demo_comprehensive_workflow():
    """포괄적인 워크플로우"""
    print("\n" + "="*60)
    print("데모 6: 포괄적인 키 라이프사이클")
    print("="*60)
    
    client = KMIPClient()
    
    # 1. 여러 프로젝트용 키 생성
    print("\n[1] 여러 프로젝트의 키 생성...")
    projects = ["web-app", "mobile-app", "api-service"]
    environments = ["dev", "staging", "production"]
    
    all_keys = []
    for project in projects:
        for env in environments:
            key_data = client.create_key("AES", 256, {
                "AlternateName": [f"{project}-{env}-key"],
                "project": project,
                "environment": env,
                "created_at": datetime.now().isoformat(),
                "status": "active"
            })
            all_keys.append(key_data["key_id"])
            print(f"    ✓ {project}/{env}: {key_data['key_id']}")
    
    # 2. 프로덕션 키만 검색
    print("\n[2] 프로덕션 키 검색...")
    prod_keys = client.locate_keys(attributes={"environment": "production"})
    print(f"    ✓ 발견된 프로덕션 키: {len(prod_keys['key_ids'])}개")
    
    # 3. 특정 프로젝트의 모든 키 검색
    print("\n[3] 'web-app' 프로젝트의 모든 키...")
    webapp_keys = client.locate_keys(attributes={"project": "web-app"})
    print(f"    ✓ 발견된 키: {len(webapp_keys['key_ids'])}개")
    
    # 4. 키에 태그 추가
    print("\n[4] 프로덕션 키에 컴플라이언스 태그 추가...")
    for key_id in prod_keys["key_ids"]:
        client.add_attributes(key_id, {
            "compliance": ["PCI-DSS", "SOC2"],
            "encryption_required": True,
            "backup_required": True
        })
    print(f"    ✓ {len(prod_keys['key_ids'])}개 키에 태그 추가됨")
    
    # 5. 정리
    print("\n[5] 정리 중...")
    for key_id in all_keys:
        client.destroy_key(key_id)
    print(f"    ✓ {len(all_keys)}개 키 삭제됨")


def main():
    """메인 함수"""
    print("\n" + "="*60)
    print("KMIP Server - 모든 오퍼레이션 데모")
    print("="*60)
    
    try:
        # 서버 연결 확인
        client = KMIPClient()
        server_info = client.query_server()
        print(f"\n서버 정보:")
        print(f"  Vendor: {server_info.get('vendor', 'Unknown')}")
        print(f"  Operations: {len(server_info.get('operations', []))}개")
        
        # 각 데모 실행
        demo_basic_operations()
        demo_attributes()
        demo_alternate_names()
        demo_key_rotation()
        demo_register_external_key()
        demo_comprehensive_workflow()
        
        print("\n" + "="*60)
        print("모든 데모 완료!")
        print("="*60 + "\n")
        
    except requests.exceptions.ConnectionError:
        print("\n❌ 오류: KMIP 서버에 연결할 수 없습니다.")
        print("   서버가 실행 중인지 확인하세요: make run-rest")
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")


if __name__ == "__main__":
    main()
