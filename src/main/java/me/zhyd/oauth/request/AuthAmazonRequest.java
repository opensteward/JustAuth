package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import com.google.common.net.HttpHeaders;
import com.xkcoding.http.constants.Constants;
import com.xkcoding.http.support.HttpHeader;
import com.xkcoding.http.util.UrlUtil;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthAmazonScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Amazon登录
 * Login with Amazon for Websites Overview： https://developer.amazon.com/zh/docs/login-with-amazon/register-web.html
 * Login with Amazon SDK for JavaScript Reference Guide：https://developer.amazon.com/zh/docs/login-with-amazon/javascript-sdk-reference.html
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
public class AuthAmazonRequest extends AuthDefaultRequest {

    public AuthAmazonRequest(AuthConfig config) {
        super(config, AuthDefaultSource.AMAZON);
    }

    public AuthAmazonRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.AMAZON, authStateCache);
    }

    /**
     * https://developer.amazon.com/zh/docs/login-with-amazon/authorization-code-grant.html#authorization-request
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return String
     */
    @Override
    public String authorize(String state) {
        String realState = getRealState(state);
        UrlBuilder builder = UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2_CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthAmazonScope.values())))
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2_RESPONSE_TYPE, Keys.OAUTH2_CODE)
                .queryParam(Keys.OAUTH2_STATE, realState);

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(realState);
            String codeVerifier = PkceUtil.generateCodeVerifier();
            String codeChallengeMethod = "S256";
            String codeChallenge = PkceUtil.generateCodeChallenge(codeChallengeMethod, codeVerifier);
            builder.queryParam("code_challenge", codeChallenge)
                    .queryParam("code_challenge_method", codeChallengeMethod);
            // 缓存 codeVerifier 十分钟
            this.authStateCache.cache(cacheKey, codeVerifier, TimeUnit.MINUTES.toMillis(10));
        }

        return builder.build();
    }

    /**
     * https://developer.amazon.com/zh/docs/login-with-amazon/authorization-code-grant.html#access-token-request
     *
     * @return access token
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(9);
        form.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        form.put(Keys.OAUTH2_CODE, authCallback.getCode());
        form.put(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri());
        form.put(Keys.OAUTH2_CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret());

        if (config.isPkce()) {
            String cacheKey = this.source.getName().concat(":code_verifier:").concat(authCallback.getState());
            String codeVerifier = this.authStateCache.get(cacheKey);
            form.put("code_verifier", codeVerifier);
        }
        return getToken(form, this.source.accessToken());
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        Map<String, String> form = new HashMap<>(7);
        form.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_REFRESH_TOKEN);
        form.put(Keys.OAUTH2_REFRESH_TOKEN, authToken.getRefreshToken());
        form.put(Keys.OAUTH2_CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret());
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(form, this.source.refresh()))
                .build();

    }

    private AuthToken getToken(Map<String, String> param, String url) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add("Host", "api.amazon.com");
        httpHeader.add(Constants.CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8");
        String response = new HttpUtils(config.getHttpConfig()).post(url, param, httpHeader, false).getBody();
        JSONObject jsonObject = JSONObject.parseObject(response);
        this.checkResponse(jsonObject);
        return AuthToken.builder()
                .accessToken(jsonObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .tokenType(jsonObject.getString(Keys.OAUTH2_TOKEN_TYPE))
                .expireIn(jsonObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .refreshToken(jsonObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .build();
    }

    /**
     * 校验响应内容是否正确
     *
     * @param jsonObject 响应内容
     */
    private void checkResponse(JSONObject jsonObject) {
        if (jsonObject.containsKey(Keys.ERROR)) {
            throw new AuthException(jsonObject.getString("error_description").concat(" ") + jsonObject.getString("error_description"));
        }
    }

    /**
     * https://developer.amazon.com/zh/docs/login-with-amazon/obtain-customer-profile.html#call-profile-endpoint
     *
     * @param authToken token信息
     * @return AuthUser
     */
    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();
        this.checkToken(accessToken);

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add("Host", "api.amazon.com");
        httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(accessToken));
        String userInfo = new HttpUtils(config.getHttpConfig()).get(this.source.userInfo(), new HashMap<>(0), httpHeader, false).getBody();
        JSONObject jsonObject = JSONObject.parseObject(userInfo);
        this.checkResponse(jsonObject);

        return AuthUser.builder()
                .rawUserInfo(jsonObject)
                .uuid(jsonObject.getString("user_id"))
                .username(jsonObject.getString(Keys.NAME))
                .nickname(jsonObject.getString(Keys.NAME))
                .email(jsonObject.getString(Keys.OAUTH2_SCOPE__EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .source(source.toString())
                .token(authToken)
                .build();
    }

    private void checkToken(String accessToken) {
        String tokenInfo = new HttpUtils(config.getHttpConfig()).get("https://api.amazon.com/auth/o2/tokeninfo?access_token=" + UrlUtil.urlEncode(accessToken)).getBody();
        JSONObject jsonObject = JSONObject.parseObject(tokenInfo);
        if (!config.getClientId().equals(jsonObject.getString("aud"))) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_TOKEN);
        }
    }

    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam("user_id", authToken.getUserId())
                .queryParam("screen_name", authToken.getScreenName())
                .queryParam("include_entities", true)
                .build();
    }
}
