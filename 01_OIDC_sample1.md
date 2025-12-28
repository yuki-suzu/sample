承知いたしました。「Spring Session JDBC (PostgreSQL)」を利用する構成で、モダンな実装（Angular 17 Signals, Java 21, Spring Boot 3.2）に最適化した完全版を作成します。

バックエンドのコード自体は `HttpSession` インターフェースを使用するため大きな変更はありませんが、**依存関係と設定ファイル（application.yml）** が大きく変わります。また、DB層が加わることで考慮すべきパフォーマンスのポイントも最後にまとめました。

---

## 1. 全体フローとアーキテクチャ

**基本構成 (BFFパターン + DB Session):**

1. **Angular (DMZ):** 認証ロジックを持たず、APIを叩くだけ。401なら指示されたURLへ飛ぶ。
2. **Spring Boot (Trust):** OAuth2 Clientとして振る舞い、セッション情報を **PostgreSQL** に永続化する。
3. **PostgreSQL:** `SPRING_SESSION` テーブル群でセッションデータを管理。

### 処理シーケンス

1. **User:** ブラウザで `/ifs/hogehoge` にアクセス。
2. **Angular:** API (`/api/ifs/data`) を実行。
3. **Spring:** 未認証のため **401 Unauthorized** を返却。
* Body: `{"loginUrl": "/oauth2/authorization/cognito"}` (動的生成)


4. **Angular:**
* Interceptorが401を検知。
* 現在のパス `/ifs/hogehoge` を `sessionStorage` に保存。
* レスポンスの `loginUrl` へリダイレクト。


5. **Auth Flow:** Spring <-> Cognito 間で認証・認可。
6. **Spring:** 認証成功 (`SuccessHandler`)。
* ユーザー情報を構築し、`session.setAttribute` を実行。
* **(内部処理):** セッションオブジェクトがシリアライズされ、PostgreSQLの `SPRING_SESSION` テーブルにINSERT/UPDATEされる。
* ルート (`/`) へリダイレクト。


7. **Angular:** アプリ再起動 (`APP_INITIALIZER`)。
* `/api/ifs/session` をコール。
* **(内部処理):** SpringがCookie (`JSESSIONID`) を元にPostgreSQLからセッションを復元。
* ログイン情報を取得し、`sessionStorage` のパスへ遷移。



---

## 2. データベース準備 (PostgreSQL)

Spring Session JDBCを利用するには、専用のテーブルが必要です。
Spring Bootの設定で自動作成することも可能ですが、本番を見据えてDDLを把握しておくと良いです。

```sql
-- Spring Session 標準スキーマ (PostgreSQL用)
CREATE TABLE SPRING_SESSION (
	PRIMARY_ID CHAR(36) NOT NULL,
	SESSION_ID CHAR(36) NOT NULL,
	CREATION_TIME BIGINT NOT NULL,
	LAST_ACCESS_TIME BIGINT NOT NULL,
	MAX_INACTIVE_INTERVAL INT NOT NULL,
	EXPIRY_TIME BIGINT NOT NULL,
	PRINCIPAL_NAME VARCHAR(100),
	CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
);

CREATE UNIQUE INDEX SPRING_SESSION_IX1 ON SPRING_SESSION (SESSION_ID);
CREATE INDEX SPRING_SESSION_IX2 ON SPRING_SESSION (EXPIRY_TIME);
CREATE INDEX SPRING_SESSION_IX3 ON SPRING_SESSION (PRINCIPAL_NAME);

CREATE TABLE SPRING_SESSION_ATTRIBUTES (
	SESSION_PRIMARY_ID CHAR(36) NOT NULL,
	ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
	ATTRIBUTE_BYTES BYTEA NOT NULL,
	CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
	CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID) REFERENCES SPRING_SESSION(PRIMARY_ID) ON DELETE CASCADE
);

```

---

## 3. インフラ設定 (Nginx)

Cookie（`JSESSIONID`）を正常に動作させるため、リバースプロキシ設定は必須です。

**nginx.conf (DMZ Web Server)**

```nginx
server {
    listen 443 ssl;
    server_name dmz-web.example.com;

    # Angular アプリ
    location / {
        root /var/www/angular-app/browser;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # API & 認証プロキシ
    # Cookieのドメイン問題を解決するため、同一ドメインに見せかける
    location ~ ^/(api|login|oauth2)/ {
        proxy_pass https://trust-api.example.com; 
        
        # パスとドメインの書き換え
        proxy_cookie_path / /;
        proxy_cookie_domain trust-api.example.com dmz-web.example.com;

        # ヘッダ転送
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

```

---

## 4. Spring Boot 3.2 (Trust AP) 実装

### build.gradle

PostgreSQLドライバとJDBCセッションを追加します。

```groovy
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
    implementation 'org.springframework.boot:spring-boot-starter-jdbc' // JDBC
    implementation 'org.springframework.session:spring-session-jdbc'   // Session JDBC
    runtimeOnly 'org.postgresql:postgresql'                            // Postgres Driver
    
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}

```

### application.yml

DB接続情報とセッション設定を記述します。

```yaml
spring:
  datasource:
    url: jdbc:postgresql://db-server:5432/mydb
    username: myuser
    password: mypassword
  
  # Session設定
  session:
    store-type: jdbc
    jdbc:
      # 起動時にテーブルがない場合作成する (本番ではnever推奨)
      initialize-schema: always
      # テーブル名を変える場合
      # table-name: MY_SESSION
  
  security:
    oauth2:
      client:
        registration:
          cognito:
            client-id: ${COGNITO_CLIENT_ID}
            client-secret: ${COGNITO_CLIENT_SECRET}
            scope: openid, profile, email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            authorization-grant-type: authorization_code
        provider:
          cognito:
            issuer-uri: https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}
            user-name-attribute: username

# アプリ設定
app:
  security:
    default-provider-id: cognito

```

### JsonAuthenticationEntryPoint.java

401時にJSONを返し、Angularに次のアクション（リダイレクト先）を指示します。

```java
package com.example.trustap.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Value("${app.security.default-provider-id}")
    private String defaultProviderId;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        // /oauth2/authorization/cognito を生成
        String loginUrl = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI 
                          + "/" + defaultProviderId;

        String jsonBody = objectMapper.writeValueAsString(Map.of("loginUrl", loginUrl));
        response.getWriter().write(jsonBody);
    }
}

```

### CustomAuthenticationSuccessHandler.java

ログイン成功後、ユーザー情報をDB（Session）に保存し、トップへ戻します。

```java
package com.example.trustap.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        HttpSession session = request.getSession(); // ここでDBセッションがロードまたは作成される

        // フロントエンドに必要な情報を作成
        Map<String, Object> frontSession = new HashMap<>();
        frontSession.put("userId", oAuth2User.getAttribute("sub"));
        frontSession.put("email", oAuth2User.getAttribute("email"));
        
        // DBへ保存 (リクエスト終了時に自動コミット)
        session.setAttribute("FRONT_SESSION_INFO", frontSession);

        // Angular再起動のためルートへリダイレクト
        response.sendRedirect("/");
    }
}

```

### SecurityConfig.java

セキュリティ設定の集大成です。

```java
package com.example.trustap.config;

import com.example.trustap.security.CustomAuthenticationSuccessHandler;
import com.example.trustap.security.JsonAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JsonAuthenticationEntryPoint jsonEntryPoint;
    private final CustomAuthenticationSuccessHandler successHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF: Cookieベース (Angularのデフォルトヘッダ X-XSRF-TOKEN に対応)
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/ifs/session").permitAll() // セッション確認は未認証でも通過させる
                .requestMatchers("/api/ifs/**").authenticated()  // 業務APIは認証必須
                .anyRequest().permitAll()
            )
            // 未認証時のハンドリング (JSON返却)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jsonEntryPoint)
            )
            // OAuth2 Login設定
            .oauth2Login(oauth2 -> oauth2
                .successHandler(successHandler)
            );

        return http.build();
    }
}

```

### SessionController.java

セッション情報の取得API。

```java
package com.example.trustap.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ifs")
public class SessionController {

    @GetMapping("/session")
    public ResponseEntity<?> getSession(HttpServletRequest request) {
        // false: セッションが無ければnullを返す (新規作成しない)
        HttpSession session = request.getSession(false);
        
        if (session != null) {
            Object info = session.getAttribute("FRONT_SESSION_INFO");
            if (info != null) {
                return ResponseEntity.ok(info);
            }
        }
        // 未ログイン時は401 -> Angularはこれを見て何もしない(or ログイン画面へ)
        return ResponseEntity.status(401).build();
    }
}

```

---

## 5. Angular 17.3 (DMZ Web) 実装

### auth.types.ts

バックエンドの返却型を定義。

```typescript
export interface SessionUser {
  userId: string;
  email: string;
}

export interface AuthErrorResponse {
  loginUrl: string;
}

```

### auth.service.ts

ロジックの中枢。Signalを使用して状態管理を行います。

```typescript
import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { tap, catchError, of, Observable } from 'rxjs';
import { SessionUser, AuthErrorResponse } from './auth.types';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);
  private readonly STORAGE_KEY = 'redirect_target_url';

  // ユーザー情報を保持するSignal
  readonly currentUser = signal<SessionUser | null>(null);
  
  // ログイン状態を導出するSignal
  readonly isLoggedIn = computed(() => !!this.currentUser());

  /**
   * 起動時に実行。セッション取得とURL復元を行う
   */
  checkSession(): Observable<SessionUser | null> {
    return this.http.get<SessionUser>('/api/ifs/session').pipe(
      tap(user => {
        // ログイン成功: Signal更新 & URL復元
        this.currentUser.set(user);
        this.restoreRedirectUrl();
      }),
      catchError(() => {
        // 未ログイン: Signalクリア
        this.currentUser.set(null);
        return of(null);
      })
    );
  }

  /**
   * 401エラー時にInterceptorから呼ばれる
   */
  handleUnauthorized(error: HttpErrorResponse): void {
    const errorBody = error.error as AuthErrorResponse;
    if (errorBody?.loginUrl) {
      // 1. 現在のURLを保存 (ルート以外の場合)
      const currentUrl = window.location.pathname + window.location.search;
      if (currentUrl !== '/') {
        sessionStorage.setItem(this.STORAGE_KEY, currentUrl);
      }
      
      // 2. 指定されたURLへリダイレクト
      window.location.href = errorBody.loginUrl;
    }
  }

  private restoreRedirectUrl(): void {
    const targetUrl = sessionStorage.getItem(this.STORAGE_KEY);
    if (targetUrl) {
      sessionStorage.removeItem(this.STORAGE_KEY);
      this.router.navigateByUrl(targetUrl);
    }
  }
}

```

### auth.interceptor.ts

401を監視するインターセプター。

```typescript
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      // 401 かつ loginUrl がある場合のみ処理
      if (error.status === 401 && error.error?.loginUrl) {
        authService.handleUnauthorized(error);
      }
      return throwError(() => error);
    })
  );
};

```

### app.config.ts

アプリ初期化処理。

```typescript
import { ApplicationConfig, APP_INITIALIZER } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';
import { routes } from './app.routes';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';

function initializeAppFactory(authService: AuthService) {
  // Angular起動前にセッションチェックを行う
  return () => authService.checkSession();
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(
      withInterceptors([authInterceptor]),
      // CSRFトークン設定 (重要)
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN',
      })
    ),
    {
      provide: APP_INITIALIZER,
      useFactory: initializeAppFactory,
      deps: [AuthService],
      multi: true
    }
  ]
};

```

---

## 6. 解説と重要なポイント

JDBC Session (PostgreSQL) を利用する場合の特有の注意点とアドバイスです。

1. **シリアライズの注意 (最重要)**
* `session.setAttribute("key", value)` で保存する `value` オブジェクトは、必ず **`java.io.Serializable` を実装**している必要があります。
* `Map<String, Object>` は中身がすべてSerializableならOKですが、自作クラスを保存する場合は `implements Serializable` を忘れると実行時エラーになります。
* PostgreSQLの `ATTRIBUTE_BYTES` カラムにはJavaのオブジェクトがバイト列として保存されます。


2. **パフォーマンスとインデックス**
* Spring Session JDBCは、リクエストのたびにDBアクセス（SELECT/UPDATE）が発生します。
* `SPRING_SESSION` テーブルの `SESSION_ID` や `EXPIRY_TIME` にインデックスが貼られていること（DDL参照）を確認してください。これが無いとアクセス数増加時にDB負荷が急増します。


3. **期限切れセッションの削除**
* Redisと異なり、JDBCの場合は有効期限が切れたレコードが自動的には消えません。
* Spring Bootは自動でクリーンアップジョブを動かしますが（`spring.session.jdbc.cleanup-cron` で設定可）、アクセスが多い場合はアプリ側でやらせず、DB側のバッチ処理やイベントで削除する運用も検討してください。


4. **トランザクション管理**
* Spring Session JDBCは内部でトランザクションを使用します。アプリ側で `@Transactional` を多用している場合、トランザクションの競合や長さに注意してください（通常はフレームワークがうまく処理しますが、念頭に置いておくと良いです）。



この構成であれば、フロントエンドはモダンでステートレスな実装を保ちつつ、バックエンドは堅牢なRDBでセッション管理を行うことができます。
