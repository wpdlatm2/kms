# GS 인증 기준 대응 안정성·보안 시험 보고서

대상: pqc-kms (kmsd 백엔드 + kmsadmin 콘솔) · 시험일 2026-11-23 · 시험 환경: Windows 11(개발), Linux(golang:1.26 컨테이너, 레이스·퍼징), 111 서버(TPM, 통합)

> 이 문서는 TTA GS(Good Software) 인증의 품질특성(KS X ISO/IEC 25010) 중 **신뢰성·보안성·성능효율성·기능적합성**에 해당하는 항목을 자체 시험한 결과다. **공식 인증 시험이 아니며**, 인증기관 시험 전에 결함을 찾아 고치기 위한 사전 시험이다.

## 1. 요약

| 구분 | 결과 |
|---|---|
| 자동 시험 | 테스트 함수 52개(서브테스트 포함 136건 PASS), localhsm `kmip` 10건 PASS, 실패 0 |
| 레이스 검출기 | 전 패키지(`go test -race`, Linux) 통과 — 제품 코드의 데이터 경합 0건 |
| 퍼징 | KMIP 요청 처리기 **16,856,932회**, 복제 상태 적용기 **10,883,107회**, 텍스트 검증 15초 — 충돌·오응답 0건 |
| 취약점 분석 | `govulncheck`: 알려진 취약점 없음 |
| 정적 보안 분석 | `gosec` 27건 → 22건 해소(코드 수정 또는 근거 주석), 잔여 5건(§5) |
| 통합(111 서버, TPM) | `deploy/itest-localhsm.sh` 0 failure |
| 독립 구현체 | PyKMIP 클라이언트로 KMIP 1.0·1.2·1.4 전 흐름 |

## 2. 시험 항목과 결과

### 2.1 입력값 검증 (보안성)
| ID | 내용 | 시험 | 결과 |
|---|---|---|---|
| IV-1 | 잘못된 JSON(`{`, `[]`, `null`, 문자열·숫자), 값 뒤 쓰레기, 알 수 없는 필드, 잘못된 타입 | `TestGS_RESTInputValidation` (클라이언트·관리 양쪽 25개 사례) | 모두 4xx + 구조화된 오류, 상태 변화 0 |
| IV-2 | 알고리즘·용도·그룹·템플릿·오퍼레이션·역할의 화이트리스트 | 〃 + 관리 엔드포인트 21개 사례 | 거부 |
| IV-3 | 이름·설명·식별자: NUL, 줄바꿈, U+2028/2029, BOM, DEL, **잘못된 UTF-8**, 129자, 키당 17개 이상, 1000개 | 〃, `TestGS_TextValidation` | 거부(이름 최대 128자·16개) |
| IV-4 | 본문 크기 한도(64KiB), 쿼리 파라미터(음수·거대 수·NUL·SQL 조각) | 〃 | 400/무시, 5xx 0 |
| IV-5 | 경로 식별자: `../`, `%00`, `%2e%2e`, 10,000자, SQL·HTML·`${jndi:…}`, 포맷 문자열 | `TestGS_RESTIdentifiers` | 200/5xx 0 (404) |
| IV-6 | KMIP 구조 위반: 빈 메시지, 헤더만, 길이 4GiB, 중첩 60단계, 임의 바이트, HTTP 요청, 잘못된 타입의 속성 | `TestGS_KMIPMalformedFrames`, `TestGS_KMIPStructureViolations` | 오류 응답 또는 연결 종료, 서버 계속 정상 |
| IV-7 | KMIP 배치 상한(64), 슬로로리스(헤더 후 정지) 차단 | `TestGS_KMIPBatchCap`, `TestGS_KMIPSlowClientIsCutOff` | 거부 / 시간 내 종료 |
| IV-8 | 저장된 악성 문자열(`<script>` 등)은 데이터로만 취급, JSON 이스케이프, `nosniff`, 로그 한 줄 유지 | `TestGS_RESTHostileTextIsInert` | 통과 |
| IV-9 | 로그인 본문: 1MiB 사용자명, SQL/HTML/NUL, 잘못된 UTF-8, 타입 오류 | `TestGS_ConsoleInputValidation` | 4xx, 입력 반사 없음, 알 수 없는 사용자와 틀린 비밀번호의 응답 동일 |

### 2.2 오류 처리·정보 노출 (보안성)
| ID | 내용 | 결과 |
|---|---|---|
| EH-1 | 오류 응답은 `code`·`message`·`status`·`requestId`(+`X-Request-Id`), 5xx는 악의적 입력으로 발생하지 않음 | 통과 |
| EH-2 | 응답에 스택 트레이스·소스 경로·DB 경로·타입명·파서 내부 문구가 없음 (`TestGS_RESTNoInformationLeak`, 콘솔 로그인) | 통과(파서 문구 `unexpected EOF`는 시험 중 발견·일반화) |
| EH-3 | KMIP 연결 하나의 패닉이 서버를 멈추지 못함(연결별 `recover`) | 구현·퍼징으로 확인 |

### 2.3 인증·세션·접근통제 (보안성)
| ID | 내용 | 시험 | 결과 |
|---|---|---|---|
| AC-1 | 로그인마다 새 세션·CSRF 토큰, 식별자 길이·무작위성, 쿠키 `HttpOnly`/`SameSite=Strict`/`Secure(TLS)` | `TestGS_SessionManagement`, `TestGS_SecureCookieOverTLS` | 통과 |
| AC-2 | 위조·변조·빈·초장문 쿠키 거부, 로그아웃 후 재사용 거부, 다른 세션 영향 없음 | 〃 | 통과 |
| AC-3 | 유휴 20분·절대 8시간 만료 | 〃(시간 단축 주입) | 통과 |
| AC-4 | CSRF 토큰 불일치/없음, Origin 불일치 거부 | `TestGS_ConsoleForwardingBoundaries` | 통과 |
| AC-5 | 클라이언트가 보낸 `X-Acting-User`는 무시(위장 불가), 허용 목록 밖 경로·메서드 거부 | 〃 | 통과 |
| AC-6 | 로그인 무차별 대입 차단(5회/5분), OTP 재사용·무차별 대입 차단, 복구 코드 1회용 | `TestOTP…`, `TestLoginThrottle…` | 통과 |
| AC-7 | 권한그룹·템플릿·상위그룹·ALL·위임 관리 규칙, 관리 평면은 키 값 미반환 | `internal/kms` 권한 시험 11건, REST·KMIP 권한 시험 | 통과 |
| AC-8 | 인증서 없는 접속 거부(KMIP·REST·관리 API) | 통합·단위 | 통과 |

### 2.4 신뢰성·안정성
| ID | 내용 | 시험 | 결과 |
|---|---|---|---|
| RL-1 | 손상된 DB(빈 파일, 절반, 1바이트, 0 채움, 텍스트, 끝에 쓰레기, 첫/마지막 비트 반전)는 **열리지 않고 파일을 건드리지 않음**, 정상 파일은 다시 열림 | `TestGS_DamagedDatabaseIsRefused` | 통과 |
| RL-2 | 중단된 쓰기(임시 파일 잔존)가 시작을 막지 않음, 키 길이 오류 거부 | 〃 | 통과 |
| RL-3 | 24개 작업자의 생성·회전·폐기·템플릿·매핑·관리자 변경 동시 실행 후 **디스크 상태 = 메모리 상태**, 순번 일치, 파기된 키에 값 없음 | `TestGS_ConcurrentOperationsAndReload` | 통과 |
| RL-4 | 같은 키에 대한 동시 비활성화는 정확히 하나만 성공, 쌍·교체 관계 불변식 유지 | `TestGS_ConcurrentLifecycleKeepsInvariants` | 통과 |
| RL-5 | KMIP 150개 동시 연결 × 3 요청, 콘솔 48개 동시 세션 | `TestGS_KMIPManyConnections`, `TestGS_ConsoleConcurrency` | 통과 |
| RL-6 | DB 변조·다른 마스터키 거부 | `TestPersistenceAndTamperDetection` | 통과 |

### 2.5 성능효율성
모든 변경이 봉인된 DB 전체를 다시 쓰므로 비용이 DB 크기에 비례한다. 키 생성 1건당 시간(AES-256, 로컬 PC):

| 키 수 | 100 | 500 | 1,000 | 2,000 |
|---|---|---|---|---|
| 생성 1건 | 1.1ms | 1.4ms | 1.8ms | 2.3ms |

조회(2,000개 대상)는 20ms 미만. 수만 개 이상 규모에서는 증분 저장이 필요하다(§5).

### 2.6 기능적합성 (요약)
KMIP 1.0~3.0 전 버전 라이프사이클, PQC·클래식 키 쌍 14종, 회전, 이름 조회, localhsm 동기화, REST 최소 요청/풍부한 응답, OTP(RFC 6238 공식 벡터), 로그 분리 — 단위·통합·111 서버 end-to-end 시험으로 확인.

## 3. 시험 중 발견·수정한 결함
1. 요청 본문의 **잘못된 UTF-8이 조용히 U+FFFD로 바뀌어 저장**됨 → 본문 전체 UTF-8 검증(거부).
2. JSON 파서 내부 문구(`unexpected EOF`)가 오류 응답에 노출 → 일반화된 문구.
3. 요청 본문 뒤의 쓰레기 값이 무시됨 → 거부.
4. 이름 개수 무제한 → 키당 16개 제한, 제어문자·구분자·BOM 거부(`badText`).
5. 경로 식별자가 검증 없이 저장소까지 도달 → UUID 형태만 통과.
6. KMIP: 연결별 `recover` 없음, 한 메시지 수신 시간 무제한(슬로로리스), 배치 개수 무제한 → 각각 추가.
7. 콘솔: 브라우저가 보낸 경로의 `%3F`/`%23`가 백엔드 URL에 질의·조각을 만들 수 있음 → 경로 이스케이프. 로그아웃 쿠키에 `HttpOnly`/`SameSite` 누락 → 추가. 백엔드 `Content-Type`을 그대로 전달 → JSON 고정.
8. KMIP 정수 변환의 래핑 가능성(gosec G115) → 포화 변환.
9. (이전 단계) PyKMIP이 찾은 Create 응답의 Object Type 누락, OTP 등록 실패가 세션 만료로 표시되던 응답 코드 문제.

## 4. 재현 방법
```bash
go test ./...                                   # 단위·통합 (Windows/Linux)
docker run --rm -v <repo>:/src ... golang:1.26 go test -race ./internal/...
go test ./internal/kmipsrv -run '^$' -fuzz FuzzKMIPRequest -fuzztime 60s      # Linux에서
go test ./internal/kms -run '^$' -fuzz FuzzApplyReplicated -fuzztime 30s
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude-dir=vendor ./internal/... ./cmd/...
sudo bash deploy/itest-localhsm.sh ./hsmctl     # TPM 호스트
```
(Windows에서는 circl 패키지 계측 한계로 퍼징 빌드가 실패하므로 Linux 컨테이너를 쓴다.)

## 5. 잔여 위험·한계 (정직하게)
- **공식 인증이 아님**: 사용성(매뉴얼 평가), 이식성(현재 linux/amd64 컨테이너만), 문서 완비성은 이번 시험 범위 밖이다. 인증기관이 요구하는 결함 관리 대장·시험 케이스 형식으로의 정리는 별도 작업이다.
- **gosec 잔여 5건**: 파일 `Close` 오류 무시 3건(정리 경로, 무해), 쿠키 `Secure` 속성이 TLS 설정에 따라 동적이라는 도구 한계 2건(평문 HTTP는 루프백에서만 허용됨). 나머지 오탐성 지적 11곳은 코드 주석(`#nosec` + 근거)에 이유를 적었다(운영자가 지정한 경로, RFC 6238의 HMAC-SHA1).
- **TOTP는 SHA-1**: 모든 인증 앱과의 호환을 위한 RFC 6238 기본값이다(HMAC이라 충돌 저항성은 필요 없음).
- **롤백 공격**: DB 파일을 이전 시점의 정상 파일로 되돌리는 공격은 막지 못한다(변조는 막음). 순번(`seq`)을 외부에 고정하는 방법(TPM 카운터)은 미구현.
- **확장성**: 변경마다 전체 DB를 다시 쓰므로 수만 건 이상에서는 느려진다(§2.5).
- **고가용성 미완성**: 복제 훅(순번, `Replicator`, 리더 아님 오류 코드)까지만 준비되어 있고 Raft 노드는 구현하지 않았다.
- 서비스 거부(대량 트래픽) 방어는 연결 수(256)·본문·배치·수신 시간 한도에 한하며, 속도 제한(rate limit)은 없다.
- KMIP 3.0은 사양 기준 구현이다(3.0 상대로 검증하지 못함).
