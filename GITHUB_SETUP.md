# 🚀 GitHub 저장소에 코드 업로드하기

## 방법 1: 커맨드라인으로 업로드 (추천)

### 1단계: 압축 파일 다운로드 및 해제

```bash
# 압축 파일 다운로드 (Claude가 제공한 파일)
# kmip-server-complete.tar.gz

# 압축 해제
tar -xzf kmip-server-complete.tar.gz
cd outputs
```

### 2단계: Git 저장소 초기화

```bash
# Git 초기화
git init

# 원격 저장소 연결
git remote add origin https://github.com/wpdlatm2/kms.git

# 또는 이미 연결되어 있다면
git remote set-url origin https://github.com/wpdlatm2/kms.git
```

### 3단계: .gitignore 생성

```bash
cat > .gitignore << 'GITIGNORE'
# 데이터 디렉토리
volumes/
data/
*.log
backup/
backups/

# 빌드 아티팩트
*.tar.gz
*.zip
kmip-server

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# 환경 변수 및 비밀 정보
.env
*.key
*.pem
config/*.yaml
!config/example.yaml

# 임시 파일
*.tmp
GITIGNORE
```

### 4단계: 커밋 및 푸시

```bash
# 모든 파일 추가
git add .

# 커밋
git commit -m "Initial commit: Complete KMIP server implementation

Features:
- KMIP 1.0-3.0 protocol support (AES, RSA, SEED, ARIA)
- Raft-based replication with 3 modes (Quorum, Sync, Async)
- Cross-cluster replication for multi-DC
- Docker containerization with auto backup
- ACL & RBAC (Admin, Owner, Guest, Audit roles)
- Group-based permissions with unlimited ACLs
- Owner can view group audit logs
- Self-permission query for all users
- Complete audit logging
- Input validation (SQL injection, XSS prevention)
- Swagger API documentation
- Auto backup with retention policies
- Log rotation with syslog support"

# 메인 브랜치로 변경
git branch -M main

# GitHub에 푸시
git push -u origin main
```

## 방법 2: GitHub CLI 사용

```bash
# GitHub CLI 설치
# Mac
brew install gh

# Ubuntu/Debian
sudo apt install gh

# Windows
# https://cli.github.com/ 에서 다운로드

# 인증
gh auth login

# 저장소 푸시
cd outputs
git init
git add .
git commit -m "Initial commit: Complete KMIP server"
git branch -M main
gh repo create wpdlatm2/kms --public --source=. --remote=origin --push
```

## 방법 3: GitHub Desktop 사용

1. **GitHub Desktop 다운로드**
   - https://desktop.github.com/

2. **로컬 저장소 추가**
   - `File` → `Add Local Repository`
   - `outputs` 폴더 선택

3. **커밋**
   - 변경사항 확인
   - 커밋 메시지 입력
   - `Commit to main` 클릭

4. **저장소 퍼블리시**
   - `Publish repository` 클릭
   - Repository name: `kms`
   - `Publish repository` 클릭

## 방법 4: GitHub 웹 인터페이스

1. **저장소 페이지 접속**
   - https://github.com/wpdlatm2/kms

2. **파일 업로드**
   - `Add file` → `Upload files`
   - 압축 해제된 파일들을 드래그 앤 드롭
   - 커밋 메시지 입력
   - `Commit changes` 클릭

## 📋 업로드 후 확인사항

### 1. README.md 확인

저장소 루트에 README.md가 표시되는지 확인하세요.

### 2. 주요 문서 확인

다음 문서들이 모두 업로드되었는지 확인:

- ✅ README.md
- ✅ DOCKER_GUIDE.md
- ✅ ACL_GUIDE.md
- ✅ ACL_QUICKSTART.md
- ✅ SWAGGER_GUIDE.md
- ✅ INPUT_VALIDATION_GUIDE.md
- ✅ BACKUP_LOG_GUIDE.md
- ✅ CROSS_CLUSTER_GUIDE.md

### 3. 디렉토리 구조 확인

```
kms/
├── README.md
├── Dockerfile
├── docker-compose.yml
├── docker-compose.multi-cluster.yml
├── Makefile.docker
├── kmip/                    # Go 소스 코드
│   ├── acl.go
│   ├── acl_handlers.go
│   ├── acl_middleware.go
│   ├── rest_api.go
│   ├── swagger_spec.go
│   └── ...
├── scripts/                 # 스크립트
│   ├── docker-setup.sh
│   ├── backup-scheduler.sh
│   ├── log-rotation.sh
│   └── ...
├── config/                  # 설정 파일 예제
└── docs/                    # 문서
```

## 🔧 초기 설정 (업로드 후)

### 1. GitHub Actions 설정 (선택사항)

```yaml
# .github/workflows/build.yml
name: Build and Test

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    - name: Build
      run: go build -v ./...
    - name: Test
      run: go test -v ./...
```

### 2. 릴리스 생성

```bash
# 태그 생성
git tag -a v1.0.0 -m "Initial release: Complete KMIP server"
git push origin v1.0.0

# 또는 GitHub 웹에서
# Releases → Create a new release → v1.0.0
```

### 3. 라이선스 파일 추가 (선택사항)

```bash
# Apache License 2.0
curl https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
git add LICENSE
git commit -m "Add Apache 2.0 license"
git push
```

## 🎯 완료 체크리스트

- [ ] 코드가 GitHub에 업로드되었는가?
- [ ] README.md가 표시되는가?
- [ ] 모든 문서가 업로드되었는가?
- [ ] .gitignore가 적용되었는가?
- [ ] 민감한 정보(API 키, 인증서)가 제외되었는가?
- [ ] 빌드가 정상적으로 되는가?

## 💡 팁

### Git 히스토리 정리 (처음 업로드 시)

```bash
# 모든 히스토리를 하나의 커밋으로
git checkout --orphan latest_branch
git add -A
git commit -m "Initial commit: Complete KMIP server"
git branch -D main
git branch -m main
git push -f origin main
```

### 대용량 파일 제외

```bash
# 100MB 이상 파일 찾기
find . -type f -size +100M

# .gitignore에 추가
echo "large-file.tar.gz" >> .gitignore
```

### 브랜치 전략

```bash
# 개발 브랜치 생성
git checkout -b develop
git push -u origin develop

# 기능 브랜치
git checkout -b feature/new-algorithm
```

## 🆘 문제 해결

### 푸시 거부됨

```bash
# 강제 푸시 (주의!)
git push -f origin main

# 또는 pull 후 merge
git pull origin main --allow-unrelated-histories
git push origin main
```

### 파일 크기 초과

```bash
# Git LFS 설치
git lfs install

# 대용량 파일 추적
git lfs track "*.tar.gz"
git add .gitattributes
git commit -m "Add Git LFS tracking"
```

### 인증 오류

```bash
# Personal Access Token 사용
# Settings → Developer settings → Personal access tokens
# repo 권한 부여 후 생성된 토큰을 비밀번호로 사용

# 또는 SSH 키 사용
ssh-keygen -t ed25519 -C "your_email@example.com"
# ~/.ssh/id_ed25519.pub 내용을 GitHub에 등록
```

## 📞 도움말

- GitHub 문서: https://docs.github.com/
- Git 가이드: https://git-scm.com/book/ko/v2
- GitHub CLI: https://cli.github.com/manual/

---

**성공적으로 업로드되길 바랍니다! 🚀**
