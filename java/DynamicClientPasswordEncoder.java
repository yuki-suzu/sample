package com.example.config;

import com.example.security.JsonClientService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * プレフィックスおよびクライアント設定に応じて動的にパスワード検証を行うカスタム {@link PasswordEncoder}。
 * 
 * <p>以下のパスワード検証ルールを提供します：</p>
 * <ul>
 *   <li>クライアントが通常（ダミー認証）の場合：パスワード入力が存在すれば常に適合</li>
 *   <li>クライアントが厳格認証を要求する場合：
 *     <ul>
 *       <li>{@code {noop}} プレフィックス：平文文字列一致検証</li>
 *       <li>{@code {bcrypt}} プレフィックス：プレフィックスを除去した BCrypt ハッシュ検証</li>
 *       <li>プレフィックスなし：そのまま BCrypt ハッシュ検証</li>
 *     </ul>
 *   </li>
 * </ul>
 */
@Component
public class DynamicClientPasswordEncoder implements PasswordEncoder {

    private static final Logger log = LoggerFactory.getLogger(DynamicClientPasswordEncoder.class);

    private static final String PREFIX_NOOP = "{noop}";
    private static final String PREFIX_BCRYPT = "{bcrypt}";

    private final JsonClientService jsonClientService;
    private final PasswordEncoder bcryptEncoder = new BCryptPasswordEncoder();
    private final RequestCache requestCache = new HttpSessionRequestCache();

    /**
     * コンストラクタ。
     *
     * @param jsonClientService クライアント設定取得サービス
     */
    public DynamicClientPasswordEncoder(JsonClientService jsonClientService) {
        this.jsonClientService = jsonClientService;
    }

    /**
     * パスワードを暗号化（BCryptハッシュ化）します。
     *
     * @param rawPassword 暗号化前の生パスワード
     * @return BCrypt によってハッシュ化されたパスワード文字列
     */
    @Override
    public String encode(CharSequence rawPassword) {
        return bcryptEncoder.encode(rawPassword);
    }

    /**
     * 生パスワードと保持パスワードの適合性を検証します。
     * 
     * <p>クライアントが厳格認証を要求している場合、保持パスワードのプレフィックス（{@code {noop}} / {@code {bcrypt}}）
     * または生ハッシュ値の形式に応じた比較を行います。</p>
     *
     * @param rawPassword ユーザーが入力した生パスワード
     * @param encodedPassword JSON等に保持されているパスワード（平文またはハッシュ値）
     * @return 認証に成功した場合は {@code true}、失敗した場合は {@code false}
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // パスワード入力がない場合は不適合
        if (rawPassword == null || rawPassword.length() == 0) {
            return false;
        }

        String clientId = getCurrentClientId();

        // 厳格認証を要求するクライアントの場合のみ詳細検証を実施
        if (jsonClientService.isStrictAuth(clientId)) {
            if (encodedPassword == null || encodedPassword.isBlank()) {
                return false;
            }

            return verifyPassword(rawPassword.toString(), encodedPassword);
        }

        // 通常クライアント（ダミー認証）は入力があれば通過
        return true;
    }

    /**
     * 保持パスワードのプレフィックスに応じた検証を実行します。
     *
     * @param rawPassword     ユーザー入力の生パスワード
     * @param encodedPassword 保持用パスワード文字列
     * @return 一致した場合は {@code true}
     */
    private boolean verifyPassword(String rawPassword, String encodedPassword) {
        // 1. {noop}プレフィックス：平文比較
        if (encodedPassword.startsWith(PREFIX_NOOP)) {
            String plainPassword = encodedPassword.substring(PREFIX_NOOP.length());
            return rawPassword.equals(plainPassword);
        }

        // 2. {bcrypt}プレフィックス：プレフィックスを除去してBCrypt比較
        if (encodedPassword.startsWith(PREFIX_BCRYPT)) {
            String cleanHash = encodedPassword.substring(PREFIX_BCRYPT.length());
            return matchesBcryptSafe(rawPassword, cleanHash);
        }

        // 3. プレフィックスなし：そのままBCrypt比較
        return matchesBcryptSafe(rawPassword, encodedPassword);
    }

    /**
     * BCrypt検証を安全に実行し、不正なハッシュ形式による例外発生時は {@code false} を返します。
     *
     * @param rawPassword 生パスワード
     * @param hash        BCryptハッシュ文字列
     * @return 検証結果
     */
    private boolean matchesBcryptSafe(String rawPassword, String hash) {
        try {
            return bcryptEncoder.matches(rawPassword, hash);
        } catch (IllegalArgumentException e) {
            log.warn("[PasswordEncoder] 不正なBCryptハッシュ形式です: {}", hash);
            return false;
        }
    }

    /**
     * HTTP リクエストまたは退避リクエストから {@code client_id} を抽出します。
     *
     * @return 検出されたクライアントID文字列。取得できない場合は {@code null}
     */
    private String getCurrentClientId() {
        ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) return null;

        HttpServletRequest request = attributes.getRequest();
        HttpServletResponse response = attributes.getResponse();

        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isBlank()) {
            return clientId;
        }

        if (response != null) {
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            if (savedRequest != null) {
                String[] clientIds = savedRequest.getParameterValues("client_id");
                if (clientIds != null && clientIds.length > 0) {
                    return clientIds[0];
                }
            }
        }

        return null;
    }
}
