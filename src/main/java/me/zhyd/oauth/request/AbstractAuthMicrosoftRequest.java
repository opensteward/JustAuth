package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import com.xkcoding.http.support.HttpHeader;
import com.xkcoding.http.util.MapUtil;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.constant.Headers;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthMicrosoftScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.StringUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.Map;

/**
 * 微软登录抽象类,负责处理使用微软国际和微软中国账号登录第三方网站的登录方式
 *
 * @author mroldx (xzfqq5201314@gmail.com)
 * @since 1.16.4
 */
public abstract class AbstractAuthMicrosoftRequest extends AuthDefaultRequest {

    public AbstractAuthMicrosoftRequest(AuthConfig config, AuthSource source) {
        super(config, source);
    }


    public AbstractAuthMicrosoftRequest(AuthConfig config, AuthSource source, AuthStateCache authStateCache) {
        super(config, source, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return getToken(accessTokenUrl(authCallback.getCode()));
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl) {
        HttpHeader httpHeader = new HttpHeader();

        Map<String, String> form = MapUtil.parseStringToMap(accessTokenUrl, false);

        String response = new HttpUtils(config.getHttpConfig()).post(accessTokenUrl, form, httpHeader, false).getBody();
        JSONObject accessTokenObject = JSONObject.parseObject(response);

        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .expireIn(accessTokenObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .scope(accessTokenObject.getString(Keys.OAUTH2_SCOPE))
                .tokenType(accessTokenObject.getString(Keys.OAUTH2_TOKEN_TYPE))
                .refreshToken(accessTokenObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        if (object.containsKey("error")) {
            throw new AuthException(object.getString("error_description"));
        }
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String token = authToken.getAccessToken();
        String tokenType = authToken.getTokenType();
        String jwt = tokenType + " " + token;

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(Headers.AUTHORIZATION, jwt);

        String userInfo = new HttpUtils(config.getHttpConfig()).get(userInfoUrl(authToken), null, httpHeader, false).getBody();
        JSONObject object = JSONObject.parseObject(userInfo);
        this.checkResponse(object);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString("id"))
                .username(object.getString("userPrincipalName"))
                .nickname(object.getString("displayName"))
                .location(object.getString("officeLocation"))
                .email(object.getString("mail"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 刷新access token （续期）
     *
     * @param authToken 登录成功后返回的Token信息
     * @return AuthResponse
     */
    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(refreshTokenUrl(authToken.getRefreshToken())))
                .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        // 兼容 Microsoft Entra ID 登录（原微软 AAD）
        // @since 1.16.6
        String tenantId = StringUtils.isEmpty(config.getTenantId()) ? "common" : config.getTenantId();
        return UrlBuilder.fromBaseUrl(String.format(source.authorize(), tenantId))
                .queryParam(Keys.OAUTH2_RESPONSE_TYPE, Keys.OAUTH2_CODE)
                .queryParam(Keys.OAUTH2_CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2_STATE, getRealState(state))
                .queryParam("response_mode", "query")
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthMicrosoftScope.values())))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code 授权code
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code) {
        String tenantId = StringUtils.isEmpty(config.getTenantId()) ? "common" : config.getTenantId();
        return UrlBuilder.fromBaseUrl(String.format(source.accessToken(), tenantId))
                .queryParam(Keys.OAUTH2_CODE, code)
                .queryParam(Keys.OAUTH2_CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthMicrosoftScope.values())))
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户授权后的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo()).build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param refreshToken 用户授权后的token
     * @return 返回获取accessToken的url
     */
    @Override
    protected String refreshTokenUrl(String refreshToken) {
        String tenantId = StringUtils.isEmpty(config.getTenantId()) ? "common" : config.getTenantId();
        return UrlBuilder.fromBaseUrl(String.format(source.refresh(), tenantId))
                .queryParam(Keys.OAUTH2_CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2_REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_REFRESH_TOKEN)
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthMicrosoftScope.values())))
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .build();
    }
}
