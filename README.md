# pqc-kms

키 관리 서버(KMIP + REST) 백엔드 **kmsd**, 웹 관리 콘솔 **kmsadmin**, 그리고 localhsm(TPM 보호 키스토어)과의 연계. 모두 Go, 외부 KMS 제품에 의존하지 않는다.

```
                         ┌──────────── kmsd (백엔드) ────────────┐
 앱 / localhsm ──KMIP────▶│ :5696  클라이언트 평면 (mTLS)          │  클라이언트 로그
 앱 ──────────REST───────▶│ :9998  클라이언트 REST (mTLS)          │  (client.log.jsonl)
 콘솔·관리자 ──admin API──▶│ :9999  관리 평면 (mTLS)  ← 별도 포트   │  관리 API 로그
                         │  암호화 DB(kms.db) ← 마스터키는 TPM     │  (admin.log.jsonl)
                         └────────────────────────────────────────┘
 브라우저 ──https+OTP──▶ kmsadmin :8443 ──(사용자를 대신해) admin API
```

## 권한 모델

| 개념 | 설명 |
|---|---|
| **서비스(권한그룹)** | 키는 반드시 **하나의 서비스**에 속한다. 서비스 단위로 권한을 준다. |
| **상위그룹** | 여러 서비스를 묶는다. 상위그룹에 준 권한·관리 권한은 소속 서비스 전체에 적용된다. |
| **ALL** | 모든 상위그룹·서비스에 적용되는 특수 그룹. 여기에 매핑된 클라이언트는 그룹과 무관하게 해당 템플릿의 권한을 갖는다. |
| **권한 템플릿** | 오퍼레이션 묶음. 기본 `owner`(생성·조회·수정·삭제 = CRUD), `guest`(조회만 = R). 오퍼레이션을 골라 새로 만들고 수정할 수 있다(UI·API). |
| **클라이언트 매핑** | 클라이언트(인증서 CN) → (서비스 \| 상위그룹 \| ALL) + 템플릿. |
| **관리자 위임** | 관리 권한(`admin` 관리 / `audit` 조회)을 ALL·상위그룹·서비스 범위로 위임. 상위그룹 관리자는 그 안에서 서비스 생성, 매핑, 관리자 지정이 가능하고 범위 밖은 못 한다. 템플릿 편집, 상위그룹 생성, 로그 열람은 전역 관리자·감사자만. |

오퍼레이션: `create`(C) · `locate` `getattributes` `get`(R) · `activate` `revoke` `rekey` `setattribute`(U) · `destroy`(D).
관리 평면은 **키 값을 절대 돌려주지 않는다**(관리자도 `get` 권한이 있는 클라이언트 매핑 없이는 값을 못 본다). 권한이 없는 객체는 "없음"으로 응답해 존재 자체를 숨긴다.

## 키 종류 (생성·보관·수명주기 관리)

AES-128/192/256 · ARIA · SEED · ChaCha20 · HMAC-SHA256/384/512 · RSA-2048/3072/4096 · EC P-224/256/384/521 · Ed25519 · Ed448 · X25519 · X448 ·
**양자내성**: ML-DSA-44/65/87 (FIPS 204) · SLH-DSA 12종 (FIPS 205) · ML-KEM-512/768/1024 (FIPS 203) · X25519MLKEM768 · X-Wing.
서버는 키 **관리**(생성, 보관, 회전, 폐기)만 하며 암·복호화·서명 연산은 하지 않는다. 그래서 연산 수단이 없는 알고리즘도 똑같이 관리된다.
라이프사이클: Pre-Active → Active → Deactivated → Destroyed, Compromised → Destroyed Compromised. 키 회전(Re-key)은 새 키를 Active로 만들고 이전 키를 Deactivated(값은 계속 조회 가능)로 두며 **이름이 두 키에 남아** 이름으로 조회하는 클라이언트가 두 버전을 함께 받는다.

## 프로토콜

- **KMIP** 1.0~1.4, 2.0, 2.1, 3.0 (바이너리 TTLV, mTLS). Create, Create Key Pair, Locate, Get, Get Attributes, Add/Delete Attribute(이름), Activate, Revoke, Re-key, Destroy, Query, Discover Versions. 권한그룹은 KMIP 속성 **Object Group**으로 지정(생략 시 클라이언트의 단일 서비스).
- **REST** (클라이언트 `/v1`, 관리 `/admin/v1`): KMIP와 같은 라이프사이클이되 **KMIP 데이터타입을 쓰지 않고** 보편적 값을 쓴다.
  - 상태 `pre-active|active|deactivated|compromised|destroyed|destroyed-compromised`, 시각 RFC 3339, 알고리즘은 표준 이름(`ML-DSA-65`, family, category, standard, curve), 용도는 이름 배열, 값 인코딩 `base64|hex|pem`.
  - **요청은 최소**: 키 생성은 `{"algorithm":"aes-256"}` 한 줄(서비스가 하나뿐인 클라이언트는 `group` 생략). 응답은 최대한 많이: 상태, 모든 시각, 쌍 키·교체 관계, 값 정보(형식·크기·공개키 지문), 지금 가능한 `actions`, 내가 가진 `permissions`.
  - 오류: `{"error":{"code","message","status"},"requestId"}` (+ `X-Request-Id` 헤더).

## 로그 분리

`client.log.jsonl`(KMIP·클라이언트 REST 요청과 이벤트)과 `admin.log.jsonl`(관리 API 요청과 이벤트)은 **다른 파일**이다. 콘솔을 거친 관리 요청에는 실제 사용자와 중계 콘솔(`via`)이 함께 기록된다. 콘솔 자체의 로그인·OTP 이벤트는 `console.log.jsonl`. 콘솔의 "로그" 탭이 세 로그를 구분해 보여준다(전역 관리자·감사자만).

## 웹 콘솔과 OTP

- 로그인: 비밀번호(PBKDF2) + **OTP**. 표준 TOTP(RFC 6238, SHA-1, 6자리, 30초)라 **Android·iOS의 무료 앱**(Google Authenticator, Microsoft Authenticator, 2FAS, Aegis, FreeOTP 등)이 모두 된다.
- 첫 로그인 시 QR 코드(또는 수동 입력 키)로 등록하고 **복구 코드 10개**(1회용)를 받는다. 코드는 한 번만 인정(재사용 방지), ±30초 시계 오차 허용, 실패 5회 5분 차단. 정책 `-otp required|optional|off`(등록된 사용자는 항상 OTP 필요). 휴대폰 분실: 복구 코드, 또는 `kmsadmin otp-reset 이름`.
- 화면: 키(필터·검색·생성·상세·동작), 서비스·그룹(상위그룹 트리, 매핑·관리자), 권한 템플릿(오퍼레이션 선택 생성·수정), 클라이언트 매핑, 관리자, 로그, 라이프사이클.
- 콘솔은 사람을 인증하고 **사용자 이름을 달아** 관리 API로 전달할 뿐이며, 무엇을 할 수 있는지는 백엔드가 정한다(`-trusted-proxy`로 지정한 인증서만 가능).

## 저장소 보안

- 모든 키·메타데이터·권한은 **하나의 AES-256-GCM 암호화 파일**(`kms.db`)에 저장된다. 변조되면 열리지 않는다.
- 데이터베이스 마스터키는 `-master-hsm`으로 **localhsm 키스토어(TPM에 묶임)** 에 둔다(개발용 `-master-file` 대안). 서버 컨테이너가 `/dev/tpmrm0`로 TPM을 쓴다.
- 모든 포트는 mTLS 필수. 클라이언트 인증서 CN이 신원이다.

## 빌드·배포 (111 서버 `/docker/pqc-kms`)

```bash
bash deploy/build.sh                     # kmsd, kmsadmin (리눅스 정적 바이너리)
scp -r deploy/* server:/docker/pqc-kms/
ssh server 'cd /docker/pqc-kms && bash setup.sh --web-san 192.168.0.111 && docker compose build && docker compose up -d'
```

`setup.sh`는 멱등이다(내부 CA·인증서·첫 콘솔 사용자 `admin`·`.env`). 세 포트(5696·9998·9999)는 **127.0.0.1에만** 공개, 콘솔 `:8443`은 LAN(TLS). 첫 관리자 비밀번호는 `secrets/admin_password`. `admin`은 백엔드의 root 관리자(`-root-admin`)이며 첫 로그인에서 OTP를 등록한다.

## 테스트

`go test ./...` — 권한 모델(상위그룹·ALL·위임), 암호화 저장소(변조·잘못된 키), KMIP 서버(전 버전, PQC 키 쌍, localhsm 동기화), REST(별도 포트·로그 분리·오류 형식), 콘솔(세션·CSRF·OTP: RFC 6238 공식 벡터 포함).
독립 구현체 확인: **PyKMIP 클라이언트**로 KMIP 1.0·1.2·1.4 전 흐름(이 과정에서 Create 응답의 Object Type 누락을 발견·수정).
`deploy/itest-localhsm.sh`(TPM 호스트에서 root): 관리 API·상위그룹 매핑·localhsm 동기화·회전·템플릿 편집·침해·REST·로그 분리를 111 서버에서 end-to-end로 검증(0 failure).

### GS 인증 기준 대응 시험

입력값 검증(UTF-8·제어문자·크기·타입·경로), 오류·정보 노출, 세션·CSRF·OTP, 손상 DB, 동시성(레이스 검출기), 퍼징(KMIP 1,685만 회 등), 취약점·정적 분석(`govulncheck`, `gosec`)을 자체 시험한 결과와 시험 중 찾아 고친 결함은 [`docs/GS_TEST_REPORT.md`](docs/GS_TEST_REPORT.md)에 있다(공식 인증 시험은 아님).

## 알아둘 점

- 생성 가능한 키는 위 목록이다(Covercrypt, FPE 등 Eviden/Cosmian 전용 기능은 없음). KMIP 3.0은 사양 기준 구현이며 3.0 서버/클라이언트와는 확인하지 못했다.
- 폐기된 키는 값이 지워진 **기록**으로 남으므로, 기록만 남은 서비스는 삭제할 수 없다.
- DB 파일을 이전 시점으로 되돌리는 공격(롤백)은 막지 못한다(변조는 막음). 백업은 `kms.db`와 TPM 키 상태가 함께 필요하다(TPM 초기화 시 복호화 불가). 운영에서는 localhsm 복구키 등록을 권장한다.
- 단일 노드다. 복제 훅(순번·리더 아님 오류)까지 준비했고 Raft 노드 구현은 남아 있다. 기존 구현은 `legacy` 브랜치에 있다.
- 사내 CA 키(`pki/ca.key`)가 서버에 있다. 운영 수준에서는 별도 보관을 권장한다.
- 콘솔 코드와 KMIP 클라이언트는 localhsm 저장소의 `kmip` 패키지를 쓴다(`go.mod`의 `replace`는 개발용; localhsm 푸시 후 제거).
