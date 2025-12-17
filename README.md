# bean-iam-server

> bean-iam-server는 Spring Boot 3.3 + Spring Authorization Server 기반의 OAuth2/OIDC 인증 서버(`authServer`)와 Web BFF(`web-bff-server`) 두 모듈만으로 구성된 IAM 레퍼런스 프로젝트입니다. Google·Kakao 같은 외부 OAuth2 공급자와 자체 회원가입을 동시에 지원하며, SPA/모바일 클라이언트가 토큰을 직접 다루지 않고도 인증을 완료하도록 설계되었습니다.

## ✨ 핵심 하이라이트
- **OAuth2 Authorization Server + Web BFF** 조합으로 프런트엔드가 토큰 저장·재발급을 위탁
- **Redis Authorization Store + MySQL User Store**를 기반으로 Authorization/Token TTL을 세밀하게 관리
- **외부 OAuth2 로그인(Google/Kakao) + 자체 회원가입**을 하나의 사용자 풀에서 통합 처리
- **HttpOnly 쿠키 전략**으로 Access/Refresh 토큰을 안전하게 브라우저에 배포하고 자동 갱신
- `commonLib`, `infra` 모듈로 상수/HTTP 상태, ObjectMapper, Redis/WebClient 설정을 공유하여 두 서비스 간 중복 제거

## 🏗️ 아키텍처 개요
```
             ┌────────────────────┐
             │   Frontend (SPA)   │
             └──────────┬─────────┘
                        │ HttpOnly Cookie + CORS
                        ▼
┌────────────────────┐ 9091 ┌────────────────────┐ 9090 ┌────────────────────┐
│   Web BFF Server   │◄────►│   Auth Server      │◄────►│  Google / Kakao    │
│ (OAuth2 Client +   │      │ (OAuth2 + OIDC +   │      │  외부 OAuth2 IdP   │
│  Resource Server)  │      │  Form Login)       │      └────────────────────┘
└──────────┬─────────┘      └──────────┬─────────┘
           │ JWT Proxy                 │ Authorization / Token 관리
           │ (HttpOnly 쿠키 ↔ Header)  │
           ▼                           ▼
        HttpOnly Cookie            Redis 6379
                                      │
                                      ▼
                                 MySQL 8 (User DB)
```

## 🔍 모듈 구성
| 모듈 | 설명 | 기본 포트 | 주요 기술 |
| --- | --- | --- | --- |
| `authServer` | OAuth2/OIDC Authorization Server + 사용자 관리 | 9090 | Spring Authorization Server, Spring Security, Redis, JPA(MySQL), Thymeleaf |
| `web-bff-server` | SPA 전용 BFF (OAuth2 Client + Resource Server) | 9091 | Spring Security, WebClient, HttpOnly 쿠키, JWT 검증 |
| `commonLib` | 상수·에러 코드·HTTP 상태·JWK 유틸 | - | Java Library, Nimbus JOSE |
| `infra` | ObjectMapper/Redis/WebClient/PasswordEncoder 등 공통 Bean | - | Custom `@Enable*` Import, Spring Context |

## 🧩 주요 기능
### authServer
- `AuthorizationServerConfig`, `SecurityConfig`로 OAuth2/OIDC + Form Login 체인 구성
- `AuthorizationRepositoryConfig`에서 `RegisteredClient` 등록 및 Access/Refresh TTL, Redirect URI, PKCE 설정
- `RedisOAuth2AuthorizationService`가 Authorization/Token/Code 인덱스를 Redis에 저장하고 TTL을 자동 조정
- `TokenBlacklistService`로 로그아웃 Access Token을 남은 TTL 동안 차단
- `SignupController`, `login.html`, `signup.html`을 통한 로컬 가입 + 소셜 2차 가입 플로우
- Google/Kakao OAuth2 클라이언트 설정과 `CustomOidcConfig`로 ID Token claims 확장

### web-bff-server
- `AuthController`가 `/api/auth/login|callback|user/me|logout` REST 엔드포인트 제공
- `TokenService`가 Access 만료 시 Refresh를 자동 수행하고, Refresh 만료 시 `/logout` 호출 및 쿠키 삭제
- `JwtFromCookieFilter`, `CookieUtil`이 HttpOnly 쿠키를 Authorization 헤더로 변환해 백엔드 호출을 단순화
- `JwtAuthEntryPoint`가 토큰 재발급 후 `449 Retry With` 응답으로 프런트 재시도 유도
- `SecurityConfig`가 Resource Server 모드에서 Auth Server `/.well-known/jwks.json`을 사용해 JWT 서명을 검증

### commonLib
- `ErrorCode`, `LoginResult`, `CustomHttpStatus` 등 공통 상수 집합
- `Jwk` 유틸로 RSA 키 페어 생성 및 JWK 변환 지원

### infra
- `@EnableRedisConfig`, `@EnableObjMapperConfig`, `@EnableWebClientConfig` 등으로 각 서비스에 필요한 Bean 세트를 모듈 단위 제공
- ObjectMapper snake_case 설정, Redis Serializer, WebClient timeout 등을 일관성 있게 관리

## 🧱 기술 스택
- Java 17, Gradle Wrapper
- Spring Boot 3.3.5, Spring Authorization Server 1.3.x
- Spring Cloud 2023.0.3 (주로 BOM 정합성 확보 용도)
- Redis 7.x (Authorization Store), MySQL 8.x (사용자 DB)
- Thymeleaf, WebClient, SLF4J
- Docker Compose (개발용 Redis)

## 📂 디렉터리 구조
```
bean-iam-server/
├── authServer/
├── web-bff-server/
├── commonLib/
├── infra/
├── build.gradle
├── settings.gradle
├── docker-compose.yml
└── README.md
```
> 실제 저장소에는 실험용 디렉터리가 더 있을 수 있지만, 현재 실행 경로는 위 네 모듈과 루트 설정 파일에 집중되어 있습니다.

## ⚙️ 빠른 시작
### 1. 요구사항
- Java 17+
- Redis 7.x (로컬 개발 시 `docker-compose up -d`)
- MySQL 8.x (사용자 DB)
- Gradle Wrapper, Git, cURL, Docker Desktop/Colima

### 2. 환경 변수
| 변수 | 설명 | 사용 모듈 |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID`, `GOOGLE_SECRET_ID` | Google OAuth2 클라이언트 정보 | authServer |
| `KAKAO_REST_API_KEY`, `KAKAO_CLIENT_SECRET` | Kakao OAuth2 클라이언트 정보 | authServer |
| `TEST_DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | 사용자 DB 접속 정보 | authServer |
| `JWT_SECRET` | Web BFF 내부 서명/검증에 사용하는 대칭키 | web-bff-server |

**Linux/macOS**
```bash
export GOOGLE_CLIENT_ID=your-google-client-id
export GOOGLE_SECRET_ID=your-google-secret
export KAKAO_REST_API_KEY=your-kakao-key
export KAKAO_CLIENT_SECRET=your-kakao-secret
export TEST_DB_URL=jdbc:mysql://localhost:3306/bean_iam
export DB_USERNAME=bean
export DB_PASSWORD=secret
export JWT_SECRET=dev-jwt
```

**Windows(cmd)**
```cmd
set GOOGLE_CLIENT_ID=your-google-client-id
set GOOGLE_SECRET_ID=your-google-secret
set KAKAO_REST_API_KEY=your-kakao-key
set KAKAO_CLIENT_SECRET=your-kakao-secret
set TEST_DB_URL=jdbc:mysql://localhost:3306/bean_iam
set DB_USERNAME=bean
set DB_PASSWORD=secret
set JWT_SECRET=dev-jwt
```

### 3. 실행 절차
```bash
# Redis 기동
docker-compose up -d

# 전체 빌드
./gradlew clean build

# Auth Server
./gradlew :authServer:bootRun

# Web BFF
./gradlew :web-bff-server:bootRun
```
Windows 환경에서는 `gradlew.bat`를 사용하세요.

### 4. JAR 실행 (선택)
```bash
java -jar authServer/build/libs/authServer-0.0.1-SNAPSHOT.jar
java -jar web-bff-server/build/libs/web-bff-server-0.0.1-SNAPSHOT.jar
```

### 5. Health Check
- `http://localhost:9090/actuator/health` (Auth Server)
- `http://localhost:9091/actuator/health` (Web BFF)
- `http://localhost:9091/api/auth/status` (BFF 자체 상태 API)

## 🔌 API 요약
### Web BFF (9091)
| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/api/auth/login` | OAuth2 로그인 시작, Authorization Server로 리다이렉트 URL 반환 |
| GET | `/api/auth/callback` | Authorization Code 수신 후 Access/Refresh/ID Token 교환 |
| GET | `/api/auth/user/me` | 현재 사용자 정보 조회 (만료 시 자동 Refresh) |
| POST | `/api/auth/logout` | 로그아웃, 쿠키 삭제 + Auth Server 세션 종료 |

### Auth Server (9090)
| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| GET | `/oauth2/authorize` | OAuth2 Authorization Endpoint |
| POST | `/oauth2/token` | Authorization Code / Refresh Grant 처리 |
| POST | `/oauth2/revoke` | 토큰 무효화 |
| GET | `/userinfo` | OIDC 사용자 정보 |
| GET | `/.well-known/jwks.json` | JWK Set (BFF JWT 검증용) |
| GET | `/login` | Form/소셜 로그인 페이지 |
| GET/POST | `/signup` | 회원가입 및 소셜 2차 가입 |

## 🔒 보안 & 운영 메모
- `RedisOAuth2AuthorizationService`는 Authorization/Code/Token 키를 분리 저장하고, Refresh Token 만료 시 Authorization TTL을 함께 조정합니다.
- `TokenService`는 Access 만료 시 Refresh를 자동 수행하고, Refresh 만료 시 `/logout`을 호출해 Redis 세션과 쿠키를 즉시 제거합니다.
- `CookieUtil`을 통해 HttpOnly + SameSite=Lax 기본값을 유지하며, 프로덕션에서는 `secure=true`, `SameSite=None` 설정을 권장합니다.
- 외부 OAuth2 공급자(Google/Kakao) credentials는 OS 환경 변수나 Secret Manager를 사용해 주입하고, 로컬 소스에 하드코딩하지 마세요.

## 🧪 테스트 & 검증
```bash
# 전체 단위 테스트
./gradlew test

# Web BFF 상태 체크
curl -i http://localhost:9091/api/auth/status

# 사용자 정보 조회 (쿠키 필요)
curl -i --cookie "ACCESS_TOKEN=<token>" http://localhost:9091/api/auth/user/me
```

### Redis 검사
```bash
redis-cli
keys oauth2:*
get oauth2:access_token:{token}
get oauth2:refresh_token:{token}
get oauth2:code:{code}
```

### 검증 포인트
- 소셜 로그인 후 `/signup?social=true`에서 추가 정보 입력 시 MySQL `users` 테이블에 데이터가 생성되는지 확인
- Access Token 만료 → 자동 Refresh·Cookie 갱신 → API 재호출이 성공적으로 이어지는지 점검
- Refresh Token 만료 시 `/logout` 호출과 함께 Redis Authorization, 블랙리스트 키가 정리되는지 확인

### 모니터링
- Actuator 엔드포인트 활용 (`/actuator/health`, `/actuator/metrics`)
- Redis 메모리 사용량 모니터링
- 토큰 갱신 빈도 추적

## 🗺️ 진행 예정 (Roadmap)

### 단기 계획
- [ ] **app-bff-server 모듈 개발**
  - 모바일 앱 전용 BFF 서버 구축
  - 기존 `web-bff-server`와 동일한 OAuth2/OIDC 클라이언트 패턴 적용
  - 모바일 앱 특화 토큰 관리 및 API 프록시 제공

### 중장기 계획
- [ ] **미용실 매장 관리 앱과의 통합**
  - 별도 프로젝트로 개발 중인 미용실 매장 관리 앱과 `bean-iam-server` 통합
  - 현재 `authServer`를 **통합 인증 서버(Unified Auth Server)**로 활용
  - 미용실 앱 사용자 인증/권한 관리를 중앙화
  - `app-bff-server`를 통해 모바일 앱과 통합 인증 서버 간 OAuth2/OIDC 플로우 연결

### 향후 확장 아이디어
- [ ] Config Server / 중앙 환경 설정
- [ ] 다중 OAuth2 클라이언트, PKCE, Device Flow 등 추가 플로우
- [ ] Web BFF에서 SSE/WebSocket/GraphQL 프록시 패턴 실험
- [ ] Observability (Prometheus, Zipkin, Grafana) 연동
- [ ] 토큰 만료 알림 및 사전 갱신 메커니즘

## 🤝 기여하기
1. Fork & Clone
2. `git checkout -b feature/my-feature`
3. `./gradlew test`
4. `git commit -m "Add my feature"`
5. Pull Request 생성

## 📄 라이선스
MIT License – `LICENSE` 참고.

