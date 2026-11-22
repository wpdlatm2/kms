# localhsm

전체 아키텍처 문서: [docs/ARCHITECTURE.pdf](docs/ARCHITECTURE.pdf) (원본: docs/architecture.html)

단일 애플리케이션용 Local HSM (Go). 의존성: CPU 기능 탐지에 golang.org/x/sys/cpu, Linux TPM 백엔드에 go-tpm, 벤치마크 도구(hsmbench)에만 x/crypto. 암호 연산은 표준 라이브러리.

```
TPM(CPU 내장 fTPM, 비내보내기 RSA-2048) ──wrap──▶ 마스터키(32B)
마스터키 ──AES-GCM──▶ 키스토어의 개별 키(버전별)
마스터키 ──HKDF──▶ 키스토어 파일 전체 MAC (키 삭제/교체 변조 탐지)
대량 연산: AES-GCM / HMAC-SHA256 / Ed25519 (Go 표준 라이브러리, AES-NI)
```

## 사용

```go
p, _ := localhsm.AvailableProtector("myapp", false) // TPM 없으면 에러 (true면 DPAPI 소프트웨어 폴백)
h, _ := localhsm.Create("app.keystore.json", p)     // 이후엔 localhsm.Open(path, p)
defer h.Close()

h.GenerateKey("data", localhsm.AES256GCM)
ct, _ := h.Encrypt("data", []byte("secret"), []byte("context-aad"))
pt, _ := h.Decrypt("data", ct, []byte("context-aad"))

h.RotateKey("data") // 구버전은 복호화 전용으로 유지
```

기능: 키 생성/로테이션/버전 비활성화/삭제, AES-256-GCM, HMAC-SHA256, Ed25519 서명(공개키만 export),
`Destroy()`(TPM 키 삭제 = crypto-erase).

## 보안 모델과 한계 (정직하게)

- 마스터키는 **TPM 안에서만 복호화**되지만, 열려 있는 동안 **프로세스 메모리에 평문으로 존재**한다
  (Close 시 zeroize). TPM이 AES/HMAC를 직접 수행하는 구조가 아니다 — NCrypt 플랫폼 공급자는
  비대칭 키 위주라 대량 연산은 CPU(AES-NI)가 한다. 프로세스 메모리를 읽을 수 있는 공격자에겐 무력.
- 키스토어 파일 + 같은 머신의 TPM이 있어야 복호화 가능. 파일만 유출되면 안전, TPM 초기화/기판 교체 시 복구 불가(백업 별도).
- AES-GCM 랜덤 96비트 nonce: 키 버전당 2^32 메시지 이내에서 로테이션할 것.
- DPAPI 폴백은 하드웨어 보호가 아니다(같은 Windows 사용자 권한이면 복호화 가능).
- 플랫폼: Windows(CNG/NCrypt)와 Linux(TPM 2.0, `/dev/tpmrm0`) 지원, 두 OS가 하나의 키스토어를 공유할 수 있다. 소프트웨어 보호자(DPAPI)는 Windows 전용이며 Linux에서는 TPM 또는 복구키만 쓴다.

## 테스트

`go test ./...` — TPM이 있으면 실제 TPM 경로도 검증하고, 없으면 해당 테스트는 skip.

## 이중화 / 부하분산: 여러 노드가 같은 마스터키 사용

TPM 키는 내보낼 수 없으므로 마스터키를 노드 간에 **복사하지 않는다.** 키스토어에 *수신자(recipient)* 를 여러 개 두고,
같은 마스터키를 **각 노드 TPM 공개키로 따로 감싼 사본**을 저장한다. 어느 노드든 자기 TPM으로 같은 키스토어를 연다.

```
키스토어 파일 ─ recipients: [ node-A(TPM-A 공개키로 wrap), node-B(TPM-B로 wrap), recovery(오프라인 키로 wrap) ]
              ─ keys: 마스터키로 wrap된 개별 키들   ─ serial / MAC
```

**노드 합류** (비밀은 네트워크를 지나지 않고 공개키만 오간다)
```go
// 새 노드 B
req, _ := localhsm.NewJoinRequest(protectorB, "node-b")   // JSON으로 관리자에게 전달 (req.ID 지문을 별도 채널로 대조)
// 이미 등록된 노드 A (관리자)
hsmA.AddRecipient(req)                                     // 갱신된 키스토어 파일을 B에 배포
// B
hsmB, _ := localhsm.Open(path, protectorB)
```

**운영 규칙**
- **쓰기는 한 노드(관리자)만** 한다. 파일에 `serial`이 있어 동시에 쓰면 `ErrConflict`, 나머지 노드는 읽기 전용으로 두고
  주기적으로(또는 "no such key version" 시) `Reload()` 한다. `Reload`는 새 키·로테이션·마스터키 교체·폐기를 반영하고, 더 낮은 serial(롤백)은 거부한다.
- 키스토어 파일은 공유 스토리지 또는 배포(rsync 등)로 모든 노드에 같게 둔다. 파일 자체는 MAC과 래핑으로 보호되므로 노출돼도 TPM 없이는 못 연다.
- **마스터키 교체**: `RotateMasterKey()` — 모든 키를 새 마스터키로 다시 감싸고 전 수신자에게 재봉인. 다른 노드는 `Reload()`.
- **노드 폐기**: `RevokeRecipient(id)` — 수신자 제거 + 마스터키 교체. 단, 이미 마스터키를 본 노드가 구 파일 사본으로 읽는 것은 막을 수 없으므로
  침해가 의심되면 각 데이터키도 `RotateKey()` 하고 데이터를 재암호화할 것.
- **오프라인 복구키(필수 권장)**: `GenerateRecoveryKey()`로 RSA 키를 만들어 개인키를 오프라인 보관하고
  `NewJoinRequest(NewRecoveryProtector(k), "recovery")` → `AddRecipient`. 모든 TPM이 초기화/교체되었을 때 유일한 복구 경로다.
- 합류 요청은 키가 **TPM 안에 있다는 것을 증명하지 않는다**(TPM 증명/attestation 미구현). 관리자가 요청 출처와 지문을 신뢰할 수 있어야 한다.
- 노드별 TPM 키 이름과 무관하게 수신자 ID는 공개키 지문이라 중복되지 않는다. DPAPI 보호자는 공유 불가(합류 요청 거부).

## Linux 노드

- 구현: `protector_linux.go` (go-tpm, `/dev/tpmrm0`). 소유자 계층 SRK 아래 **RSA-2048 복호화 전용 키**(fixedTPM/fixedParent → 내보내기·복제 불가)를 만들어
  영구 핸들(`0x8109xxxx`, 키 이름 해시로 결정)에 저장한다. 핸들에 다른 객체가 있으면(AuthPolicy 태그 불일치) **절대 건드리지 않고** 에러를 낸다 → 키 이름을 바꿀 것.
- 래핑은 공개키로 소프트웨어 OAEP-SHA256, **언래핑만 TPM이 수행**. 수신자 ID는 공개키 지문이라 Windows/Linux 노드가 같은 키스토어에 섞여 있어도 된다.
- 프로세스 사용자가 장치에 접근할 수 있어야 한다: `usermod -aG tss <user>` (또는 root). 장치 경로는 `LOCALHSM_TPM_DEVICE`로 변경.
  Docker 컨테이너에서는 `--device /dev/tpmrm0`를 넘기고 컨테이너 사용자에게 같은 권한을 줄 것.
- 키 이름 해시 충돌 가능성은 약 1/65536 (충돌 시 위 에러로 안전하게 중단).

## hsmctl (운영용 CLI)

```
go build -o hsmctl ./cmd/hsmctl
hsmctl -ks app.keystore.json -name nodeA init
hsmctl -name nodeB -label node-b join-request > req.json      # 새 노드, 지문은 별도 채널로 대조
hsmctl -ks app.keystore.json -name nodeA add < req.json       # 기존 노드가 승인 → 파일 배포
hsmctl -ks app.keystore.json -name nodeB recipients | genkey | encrypt | decrypt | revoke | rotate-master
hsmctl -name nodeB destroy-node                                # 이 노드의 TPM 키 삭제(crypto-erase)
```

검증됨: Windows(AMD fTPM) 노드가 만든 키스토어를 Linux(111서버, TPM 2.0) 노드가 승인받아 열고 양방향으로 암복호화.

## 키 보관(Custody) 모드 — 키 값만 보관하고 연산은 앱이

HSM이 알고리즘을 구현하지 않고 **키 값만 안전하게 저장**하며, 앱이 `ExportKey`로 받아 직접 연산하는 방식도 지원한다.
SEED/ARIA/AES-XTS(512비트 키)/RSA/ECDSA/ML-KEM/ML-DSA를 저장·길이검증·버전관리한다. (AES-512는 존재하지 않음: 512비트 키는 AES-256-XTS)

```go
h.GenerateKey("db", localhsm.ARIA256)                 // 또는 ImportKey(id, type, material, opts)
k, _ := h.ExportKey("db", 0); defer k.Zeroize()       // 앱이 k.Material로 직접 암복호화
h.GenerateKeyWith("sig", localhsm.ECDSAP256, localhsm.WithExportable(false)) // 반출 불가, 공개키만 제공
h.SetAuditHook(func(e localhsm.AuditEvent) { log.Println(e.Op, e.KeyID, e.Err) })
```

⚠ 반출된 키는 앱 메모리에 존재한다(앱 침해 = 키 탈취, 회수 불가). 가능하면 `aes256-gcm`/`hmac-sha256`/`ed25519`의 HSM 연산 방식(반출 불가)을 쓰고,
앱이 직접 연산해야 하는 알고리즘에만 이 모드를 쓴다. 상세 비교: [docs/COMPARISON_custody_vs_service.pdf](docs/COMPARISON_custody_vs_service.pdf)
CLI: `hsmctl … types | genkey ID aria-256 | import ID rsa-3072 < key.pem | export ID [ver] | pubkey ID [ver]`

## 운영 모드: Stand-alone / Enterprise(KMS)

- **Stand-alone(기본)**: KMS 없이 독자 구성. localhsm이 키를 직접 생성·로테이션·연산한다. 서버가 여러 대여도 수신자 모델로 마스터키를 공유하는 독자 구성이 가능하다(쓰기 노드 1 + 읽기 노드 N).
- **Enterprise**: KMS가 키의 권위. 로컬 생성·임의 가져오기·로테이션은 금지되고, KMS가 발급한 키만 `SyncFromKMS`/`ApplyKMSKeys`로 받아 안전하게 저장한다. 상태(active/decrypt-only/disabled)·만료·반출 정책은 KMS가 정하고, `MaxSyncAge`로 동기화 지연 시 키 사용을 중단할 수 있다.

```go
h, _ := localhsm.CreateWith(path, p, localhsm.CreateOptions{Mode: localhsm.ModeEnterprise, MaxSyncAge: 24 * time.Hour})
rep, err := h.SyncFromKMS(ctx, myKMS, nil)   // myKMS: Fetch(ctx, refs) ([]KMSKey, error) 구현
```

상세: [docs/OPERATION_MODES.pdf](docs/OPERATION_MODES.pdf)

## CPU 암호 가속 점검과 성능

`localhsm.DetectCPU()`가 AES-NI, PCLMULQDQ, SHA-NI, VAES, AVX2/AVX-512(x86)와 ARMv8 AES/PMULL/SHA(arm64)를 점검한다. `hsmbench`로 처리량을 측정하고,
`go build -tags purego ./cmd/hsmbench`로 "가속 없음" 기준을 만든다. 측정 결과(AES-GCM 약 40배 등)는 [docs/CPU_ACCEL_REPORT.pdf](docs/CPU_ACCEL_REPORT.pdf) 참조.

## 봉투 암호화 (Envelope)

데이터는 앱이 DEK로 CPU 가속(AES-GCM)으로 암호화하고, **DEK만 HSM의 KEK**(aes256-gcm 키, 반출 불가)로 감싼다. KEK는 로컬 생성 키 또는 KMS 발급 키(Enterprise)를 쓸 수 있다.

```go
blob, _ := h.SealEnvelope("kek", plaintext, objectID)      // 객체마다 새 DEK (HSM 호출 1회)
pt, _ := h.OpenEnvelope("kek", blob, objectID)

dek, wrapped, _ := h.GenerateDataKey("kek", batchID)       // DEK 1개를 여러 객체에 재사용(소형 메시지에 유리)
defer clear(dek)
nw, _ := h.RewrapDataKey("kek", wrapped, batchID)          // KEK 로테이션 후 DEK만 다시 감쌈(데이터는 그대로)
```

AAD가 감싼 DEK를 객체에 묶어 바꿔치기를 막고, 감사 훅은 `datakey-generate/decrypt/rewrap` 이벤트(객체 단위)를 낸다.
성능·보안 비교: [docs/COMPARISON_custody_vs_service.pdf](docs/COMPARISON_custody_vs_service.pdf) 3.2절.

## 문서

| 문서 | 내용 |
|---|---|
| [ARCHITECTURE.pdf](docs/ARCHITECTURE.pdf) | 전체 아키텍처, 다중 노드 구성(별첨 A) |
| [OPERATION_MODES.pdf](docs/OPERATION_MODES.pdf) | Stand-alone / Enterprise(KMS) 모드 |
| [COMPARISON_custody_vs_service.pdf](docs/COMPARISON_custody_vs_service.pdf) | HSM 연산 / 키 보관 / 봉투 암호화 비교 |
| [REVIEW_no_wrapping.pdf](docs/REVIEW_no_wrapping.pdf) | wrapping 없는 구조 검토, 키 길이와 보안 강도 |
| [CPU_ACCEL_REPORT.pdf](docs/CPU_ACCEL_REPORT.pdf) | CPU 암호 가속 점검과 성능 측정 |
| [TPM_KEY_CPU_ACCEL.pdf](docs/TPM_KEY_CPU_ACCEL.pdf) | TPM 키를 CPU 가속기로 쓸 수 있는가 |
| [KMS_CREDENTIALS_AND_IV.pdf](docs/KMS_CREDENTIALS_AND_IV.pdf) | KMS 인증정보의 TPM 보관, IV 관리 |

## 커널 보관 키 (Linux)

키를 **커널이 보관**하고 앱은 데이터만 요청에 담아 결과를 받는다. 키링 `logon` 키를 거쳐 커널 AF_ALG `gcm(aes)`에 등록한 뒤 앱 쪽 사본은 지운다.
반출 불가 키도 쓸 수 있고, 키를 받은 적 없는 다른 프로세스에 복호화 전용 핸들을 넘길 수 있다.

```go
k, _ := h.OpenKernelAEAD("db-key", 0)       // aes256-gcm 또는 aes-128/192/256 키
defer k.Close()
ct, _ := k.Seal(nonce, aad, plaintext)      // ciphertext||tag
pt, _ := k.Open(nonce, aad, ct)
f, _ := k.DupFile()                          // 다른 프로세스에 핸들 전달 (키는 전달되지 않음)
```

제약: Linux 전용, 요청 1건 `MaxKernelMessage`(128KiB) 이하, 호출이 앱 내 연산보다 2.8~28배 느림, 커널 제공 알고리즘만(SEED·PQC 불가), IV(12B)는 호출자가 유일하게 관리.
검증과 측정: [docs/TPM_KEY_CPU_ACCEL.pdf](docs/TPM_KEY_CPU_ACCEL.pdf) 3.1절.

## KMS 인증정보 (Enterprise): TPM 서명 키와 로컬 비밀 저장소

- **PKI 클라이언트 인증서(mTLS)**: `NewTPMSigner`가 TPM 안에 비내보내기 ECDSA P-256 키를 만들고(Windows CNG / Linux TPM 2.0), `crypto.Signer`로 TLS 핸드셰이크·CSR에 서명한다.
  `NewKMSTLSConfig`가 클라이언트 인증서·서버 CA·서버 공개키 pin으로 `tls.Config`를 만든다. 서명 키와 다른 키로 발급된 인증서는 거부한다.
- **API 키·토큰**: `OpenSecretStore`가 노드 로컬 파일에 비밀을 AES-GCM으로 저장하고 데이터 키만 TPM으로 감싼다. 쓰기 노드(KMS와 통신하는 노드)의 로컬에 두고 공유 키스토어에는 넣지 않는다.

```
hsmctl -name node-a -cn node-a -dns node-a.internal kms-csr > node.csr   # TPM 키 생성 + CSR
hsmctl -ks app.keystore.json -name node-a secret-put kms/api-key < value
```

## KMIP로 KMS에서 키 가져오기 (Enterprise)

`kmip` 패키지는 KMIP 클라이언트이자 `localhsm.KMS` 어댑터다. **mTLS**로 접속해 **키 이름(Name)** 으로 Locate → Get Attributes → Get 하고, 받은 값을 `SyncFromKMS`로 **TPM이 보호하는 키스토어**에 저장한다. 클라이언트 인증서의 개인키는 TPM 서명키(`NewTPMSigner`)라 디스크/메모리에 나오지 않는다.

```
hsmctl -ks ks.json -name NODEKEY -kmip-addr kms.internal:5696 -kmip-cert node.crt -kmip-ca kms-ca.pem        [-kmip-pin <SPKI SHA-256 hex>] [-kmip-version 2.0] [-kmip-exportable] [-kmip-types NAME=TYPE,...] kmip-sync payments-key billing-key
```

- **버전**: KMIP 1.0~1.4, 2.0, 2.1, 3.0. 기본은 Discover Versions로 협상(미지원 서버는 1.4로 폴백), `-kmip-version`으로 고정 가능. 1.x는 `Attribute` 이름/값, 2.x 이후는 `Attributes` 구조로 속성을 주고받는다.
- **이름 → 버전**: 같은 이름의 객체가 여러 개면(키 회전) 각각이 한 *버전*이 된다. 상태 매핑: Active→active, Deactivated→decrypt-only, Pre-Active/Compromised/Destroyed→disabled(값은 요청하지 않음). 이미 저장된 버전의 값이 서버에서 바뀌면 거부한다.
- **키 종류**: AES/ARIA/SEED(Raw), RSA·ECDSA 개인키(PKCS#8/PKCS#1/SEC1 → PKCS#8로 정규화), Secret Data는 `-kmip-types`로 타입 지정. 래핑되어 오는 키(Key Wrapping Data)는 지원하지 않는다.
- **검증 범위**: 자체 mock 서버로 1.0~3.0 전 버전 + 오류 경로, **Eviden KMS 5.29.0과 자체 백엔드 pqc-kms로 1.4·2.1, 독립 구현체(PyKMIP)로 1.0/1.2/1.4** 를 실접속 확인(pqc-kms 통합 테스트는 TPM 서버에서 localhsm과 end-to-end로 통과). 3.0은 사양 기준 구현이며 해당 버전을 지원하는 실제 서버로는 아직 검증하지 못했다(3.x는 2.x 와이어 형식을 따른다고 가정). 외부 서버 시험: `KMIP_INTEROP_ADDR=... go test ./kmip -run Interop -v`.

## IV 관리 (Stand-alone / Enterprise 공통)

키마다 IV 정책을 가진다: `random`(기본) / `counter`(노드 태그 + 카운터, 재시작·노드 간 유일, 노드 로컬 상태 파일) / `static`(레거시 키+IV 쌍, 명시적 허용 필요, AES-GCM 거부).

```go
h.GenerateKeyWith("data", localhsm.AES256GCM, localhsm.KeyOptions{IV: &localhsm.IVOptions{Policy: localhsm.IVCounter}})
iv, _ := h.NextIV("data")        // HSM의 Encrypt도 같은 카운터를 nonce로 사용
```

KMS가 키와 IV를 함께 발급하는 경우 `KMSKey.IVPolicy/IVSize`, `KMSKeyVersion.IV`를 쓴다. 카운터 상태 파일을 백업에서 복원(롤백)하면 IV가 반복될 수 있으니 주의한다.
상세: [docs/KMS_CREDENTIALS_AND_IV.pdf](docs/KMS_CREDENTIALS_AND_IV.pdf)

## 배포 패키지 (`dist/`)

설치·운영에 필요한 것을 한 폴더에 모았다: 빌드 스크립트와 바이너리(Windows/Linux, 체크섬 포함), 설치·사전점검 스크립트,
예제(앱 통합, KMS 어댑터 골격, systemd, Docker, KMS 번들), 그리고 가이드 3종.

| 문서 | 내용 |
|---|---|
| [dist/docs/01_ARCHITECTURE.pdf](dist/docs/01_ARCHITECTURE.pdf) | 전체 아키텍처 |
| [dist/docs/02_INSTALL_GUIDE.pdf](dist/docs/02_INSTALL_GUIDE.pdf) | 설치 가이드 |
| [dist/docs/03_OPERATIONS_GUIDE.pdf](dist/docs/03_OPERATIONS_GUIDE.pdf) | 운영 가이드(키 라이프사이클 기준) |

패키지 사용법은 [dist/README.md](dist/README.md). 바이너리는 `bash dist/scripts/build.sh`로 생성한다(저장소에는 포함하지 않음).
