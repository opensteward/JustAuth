package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSON;
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
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.*;

/**
 * 飞书平台，企业自建应用授权登录，原逻辑由 beacon 集成于 1.14.0 版，但最新的飞书 api 已修改，并且飞书平台一直为 {@code Deprecated} 状态
 * <p>
 * 所以，最终修改该平台的实际发布版本为 1.15.9
 *
 * @author beacon
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com) 重构业务逻辑 20210101
 * @since 1.15.9
 */
public class AuthFeishuRequest extends AuthDefaultRequest {

    private static final String APP_ACCESS_TOKEN = "app_access_token";

    public AuthFeishuRequest(AuthConfig config) {
        super(config, AuthDefaultSource.FEISHU);
    }

    public AuthFeishuRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.FEISHU, authStateCache);
    }

    /**
     * 获取 app_access_token（企业自建应用）
     * <p>
     * Token 有效期为 2 小时，在此期间调用该接口 token 不会改变。当 token 有效期小于 30 分的时候，再次请求获取 token 的时候，
     * 会生成一个新的 token，与此同时老的 token 依然有效。
     *
     * @return appAccessToken
     */
    private String getAppAccessToken() {
        String cacheKey = this.source.getName().concat(":" + APP_ACCESS_TOKEN + ":").concat(config.getClientId());
        String cacheAppAccessToken = this.authStateCache.get(cacheKey);
        if (StringUtils.isNotEmpty(cacheAppAccessToken)) {
            return cacheAppAccessToken;
        }
        String url = "https://open.feishu.cn/open-apis/auth/v3/" + APP_ACCESS_TOKEN + "/internal/";
        JSONObject requestObject = new JSONObject();
        requestObject.put(Keys.VARIANT__APP_ID, config.getClientId());
        requestObject.put("app_secret", config.getClientSecret());
        String response = new HttpUtils(config.getHttpConfig()).post(url, requestObject.toJSONString(), new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)).getBody();
        JSONObject jsonObject = JSON.parseObject(response);
        this.checkResponse(jsonObject);
        String appAccessToken = jsonObject.getString(APP_ACCESS_TOKEN);
        // 缓存 app access token
        this.authStateCache.cache(cacheKey, appAccessToken, jsonObject.getLongValue("expire") * 1000);
        return appAccessToken;
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        JSONObject requestObject = new JSONObject();
        requestObject.put(APP_ACCESS_TOKEN, this.getAppAccessToken());
        requestObject.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        requestObject.put(Keys.OAUTH2_CODE, authCallback.getCode());
        return getToken(requestObject, this.source.accessToken());

    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();
        String response = new HttpUtils(config.getHttpConfig()).get(source.userInfo(), null, new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(accessToken)), false).getBody();
        JSONObject object = JSON.parseObject(response);
        this.checkResponse(object);
        JSONObject data = object.getJSONObject(Keys.DATA);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(data.getString(Keys.VARIANT__UNION_ID))
                .username(data.getString(Keys.NAME))
                .nickname(data.getString(Keys.NAME))
                .avatar(data.getString(Keys.AVATAR_URL))
                .email(data.getString(Keys.OAUTH2_SCOPE__EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        JSONObject requestObject = new JSONObject();
        requestObject.put(APP_ACCESS_TOKEN, this.getAppAccessToken());
        requestObject.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_REFRESH_TOKEN);
        requestObject.put(Keys.OAUTH2_REFRESH_TOKEN, authToken.getRefreshToken());
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(requestObject, this.source.refresh()))
                .build();

    }

    private AuthToken getToken(JSONObject param, String url) {
        String response = new HttpUtils(config.getHttpConfig()).post(url, param.toJSONString(), new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)).getBody();
        JSONObject jsonObject = JSON.parseObject(response);
        this.checkResponse(jsonObject);
        JSONObject data = jsonObject.getJSONObject(Keys.DATA);
        return AuthToken.builder()
                .accessToken(data.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .refreshToken(data.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .expireIn(data.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .tokenType(data.getString(Keys.OAUTH2_TOKEN_TYPE))
                .openId(data.getString(Keys.VARIANT__OPEN_ID))
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.VARIANT__APP_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_REDIRECT_URI, GlobalAuthUtils.urlEncode(config.getRedirectUri()))
                .queryParam(Keys.OAUTH2_STATE, getRealState(state))
                .build();
    }


    /**
     * 校验响应内容是否正确
     *
     * @param jsonObject 响应内容
     */
    private void checkResponse(JSONObject jsonObject) {
        if (jsonObject.getIntValue(Keys.OAUTH2_CODE) != 0) {
            throw new AuthException(jsonObject.getString(Keys.MESSAGE));
        }
    }

}
