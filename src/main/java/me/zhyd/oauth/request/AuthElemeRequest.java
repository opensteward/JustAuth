package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import com.xkcoding.http.constants.Constants;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Headers;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 饿了么
 * <p>
 * 注：集成的是正式环境，非沙箱环境
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.12.0
 */
public class AuthElemeRequest extends AuthDefaultRequest {

    private static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded;charset=UTF-8";
    private static final String CONTENT_TYPE_JSON = "application/json; charset=utf-8";

    public AuthElemeRequest(AuthConfig config) {
        super(config, AuthDefaultSource.ELEME);
    }

    public AuthElemeRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.ELEME, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(7);
        form.put(Keys.OAUTH2_CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri());
        form.put(Keys.OAUTH2_CODE, authCallback.getCode());
        form.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);

        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_FORM, this.getRequestId(), true);
        String response = new HttpUtils(config.getHttpConfig()).post(source.accessToken(), form, httpHeader, false).getBody();
        JSONObject object = JSONObject.parseObject(response);

        this.checkResponse(object);

        return AuthToken.builder()
                .accessToken(object.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .refreshToken(object.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .tokenType(object.getString(Keys.OAUTH2_TOKEN_TYPE))
                .expireIn(object.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        Map<String, Object> parameters = new HashMap<>(4);
        // 获取商户账号信息的API接口名称
        String action = "eleme.user.getUser";
        // 时间戳，单位秒。API服务端允许客户端请求最大时间误差为正负5分钟。
        final long timestamp = System.currentTimeMillis();
        // 公共参数
        Map<String, Object> metasHashMap = new HashMap<>(4);
        metasHashMap.put("app_key", config.getClientId());
        metasHashMap.put("timestamp", timestamp);
        String signature = GlobalAuthUtils.generateElemeSignature(config.getClientId(), config.getClientSecret(), timestamp, action, authToken
                .getAccessToken(), parameters);

        String requestId = this.getRequestId();

        Map<String, Object> paramsMap = new HashMap<>();
        paramsMap.put("nop", "1.0.0");
        paramsMap.put("id", requestId);
        paramsMap.put("action", action);
        paramsMap.put("token", authToken.getAccessToken());
        paramsMap.put("metas", metasHashMap);
        paramsMap.put("params", parameters);
        paramsMap.put("signature", signature);

        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_JSON, requestId, false);
        String response = new HttpUtils(config.getHttpConfig()).post(source.userInfo(), JSONObject.toJSONString(paramsMap), httpHeader).getBody();

        JSONObject object = JSONObject.parseObject(response);

        // 校验请求
        if (object.containsKey(Keys.NAME)) {
            throw new AuthException(object.getString("message"));
        }
        if (object.containsKey("error") && null != object.get("error")) {
            throw new AuthException(object.getJSONObject("error").getString("message"));
        }

        JSONObject result = object.getJSONObject("result");

        return AuthUser.builder()
                .rawUserInfo(result)
                .uuid(result.getString("userId"))
                .username(result.getString("userName"))
                .nickname(result.getString("userName"))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        Map<String, String> form = new HashMap<>(4);
        form.put(Keys.OAUTH2_REFRESH_TOKEN, oldToken.getRefreshToken());
        form.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_REFRESH_TOKEN);

        HttpHeader httpHeader = this.buildHeader(CONTENT_TYPE_FORM, this.getRequestId(), true);
        String response = new HttpUtils(config.getHttpConfig()).post(source.refresh(), form, httpHeader, false).getBody();

        JSONObject object = JSONObject.parseObject(response);

        this.checkResponse(object);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(object.getString(Keys.OAUTH2_ACCESS_TOKEN))
                        .refreshToken(object.getString(Keys.OAUTH2_REFRESH_TOKEN))
                        .tokenType(object.getString(Keys.OAUTH2_TOKEN_TYPE))
                        .expireIn(object.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                        .build())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state)).queryParam(Keys.OAUTH2_SCOPE, "all").build();
    }

    private HttpHeader buildHeader(String contentType, String requestId, boolean auth) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add("Accept", "text/xml,text/javascript,text/html");
        httpHeader.add(Constants.CONTENT_TYPE, contentType);
        httpHeader.add("Accept-Encoding", "gzip");
        httpHeader.add("User-Agent", "eleme-openapi-java-sdk");
        httpHeader.add("x-eleme-requestid", requestId);
        if (auth) {
            httpHeader.add(Headers.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));
        }
        return httpHeader;
    }

    private String getRequestId() {
        return (UuidUtils.getUUID() + "|" + System.currentTimeMillis()).toUpperCase();
    }

    private void checkResponse(JSONObject object) {
        if (object.containsKey("error")) {
            throw new AuthException(object.getString("error_description"));
        }
    }

}
