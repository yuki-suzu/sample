import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

    /**
     * HTTP リクエストヘッダー、パラメータ、またはセッションから {@code client_id} を抽出します。
     * 
     * <p>以下の優先順位で {@code client_id} の特定を試みます：</p>
     * <ol>
     *   <li>{@code Authorization: Basic ...} ヘッダー（Base64デコードしてユーザー名部分を取得）</li>
     *   <li>直近の HTTP リクエストパラメータ（{@code client_id}）</li>
     *   <li>セッション内の退避リクエスト（{@code SPRING_SECURITY_SAVED_REQUEST}）</li>
     * </ol>
     *
     * @return 検出されたクライアントID文字列。特定できない場合は {@code null}
     */
    private String getCurrentClientId() {
        ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return null;
        }

        HttpServletRequest request = attributes.getRequest();

        // 1. Authorization ヘッダー（Basic 認証）から client_id を抽出
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                String base64Credentials = authHeader.substring(6).trim();
                byte[] decoded = Base64.getDecoder().decode(base64Credentials);
                String credentials = new String(decoded, StandardCharsets.UTF_8);
                
                // "clientId:clientSecret" 形式から clientId を切り出し
                int colonIndex = credentials.indexOf(':');
                if (colonIndex != -1) {
                    String clientId = credentials.substring(0, colonIndex);
                    if (!clientId.isBlank()) {
                        return clientId;
                    }
                }
            } catch (Exception e) {
                log.warn("[PasswordEncoder] Basic認証ヘッダーのデコードに失敗しました", e);
            }
        }

        // 2. リクエストパラメータから client_id を取得
        String paramClientId = request.getParameter("client_id");
        if (paramClientId != null && !paramClientId.isBlank()) {
            return paramClientId;
        }

        // 3. ログイン画面経由：セッションに保存された SavedRequest から client_id を取得
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object savedRequestObj = session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (savedRequestObj instanceof SavedRequest savedRequest) {
                String[] clientIds = savedRequest.getParameterValues("client_id");
                if (clientIds != null && clientIds.length > 0 && !clientIds[0].isBlank()) {
                    return clientIds[0];
                }
            }
        }

        return null;
    }
