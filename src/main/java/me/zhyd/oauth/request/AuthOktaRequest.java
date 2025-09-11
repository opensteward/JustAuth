package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import com.google.common.net.HttpHeaders;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthOktaScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.TokenUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * Okta 登录
 * <p>
 * https://{domainPrefix}.okta.com/oauth2/default/.well-known/oauth-authorization-server
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
public class AuthOktaRequest extends AuthDefaultRequest {

    public AuthOktaRequest(AuthConfig config) {
        super(config, AuthDefaultSource.OKTA);
    }

    public AuthOktaRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.OKTA, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String tokenUrl = accessTokenUrl(authCallback.getCode());
        return getAuthToken(tokenUrl);
    }

    private AuthToken getAuthToken(String tokenUrl) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));
        String response = new HttpUtils(config.getHttpConfig()).post(tokenUrl, null, header, false).getBody();
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        this.checkResponse(accessTokenObject);
        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .tokenType(accessTokenObject.getString(Keys.OAUTH2_TOKEN_TYPE))
                .expireIn(accessTokenObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .scope(accessTokenObject.getString(Keys.OAUTH2_SCOPE))
                .refreshToken(accessTokenObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .idToken(accessTokenObject.getString(Keys.OIDC_ID_TOKEN))
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        if (null == authToken.getRefreshToken()) {
            return AuthResponse.<AuthToken>builder()
                    .code(AuthResponseStatus.ILLEGAL_TOKEN.getCode())
                    .msg(AuthResponseStatus.ILLEGAL_TOKEN.getMsg())
                    .build();
        }
        String refreshUrl = refreshTokenUrl(authToken.getRefreshToken());
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(this.getAuthToken(refreshUrl))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));
        String response = new HttpUtils(config.getHttpConfig()).post(userInfoUrl(authToken), null, header, false).getBody();
        JSONObject object = JSONObject.parseObject(response);
        this.checkResponse(object);
        JSONObject address = object.getJSONObject(Keys.OAUTH2_SCOPE__ADDRESS);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString("sub"))
                .username(object.getString(Keys.NAME))
                .nickname(object.getString(Keys.NICKNAME))
                .email(object.getString(Keys.OAUTH2_SCOPE__EMAIL))
                .location(null == address ? null : address.getString("street_address"))
                .gender(AuthUserGender.getRealGender(object.getString("sex")))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse revoke(AuthToken authToken) {
        Map<String, String> params = new HashMap<>(4);
        params.put("token", authToken.getAccessToken());
        params.put("token_type_hint", Keys.OAUTH2_ACCESS_TOKEN);

        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));
        new HttpUtils(config.getHttpConfig()).post(revokeUrl(authToken), params, header, false);
        AuthResponseStatus status = AuthResponseStatus.SUCCESS;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }

    private void checkResponse(JSONObject object) {
        if (object.containsKey(Keys.ERROR)) {
            throw new AuthException(object.getString(Keys.ERROR_DESCRIPTION));
        }
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(String.format(source.authorize(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2_RESPONSE_TYPE, Keys.OAUTH2_CODE)
                .queryParam("prompt", "consent")
                .queryParam(Keys.OAUTH2_CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthOktaScope.values())))
                .queryParam(Keys.OAUTH2_STATE, getRealState(state))
                .build();
    }

    @Override
    public String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(String.format(source.accessToken(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2_CODE, code)
                .queryParam(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(String.format(source.refresh(), config.getDomainPrefix(), config.getAuthServerId()))
                .queryParam(Keys.OAUTH2_REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_REFRESH_TOKEN)
                .build();
    }

    @Override
    protected String revokeUrl(AuthToken authToken) {
        return String.format(source.revoke(), config.getDomainPrefix(), config.getAuthServerId());
    }

    @Override
    public String userInfoUrl(AuthToken authToken) {
        return String.format(source.userInfo(), config.getDomainPrefix(), config.getAuthServerId());
    }
}
