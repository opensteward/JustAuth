package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthJdScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * 京东登录
 *
 * @author harry.lee (harryleexyz@qq.com)
 * @since 1.15.0
 */
public class AuthJdRequest extends AuthDefaultRequest {

    public AuthJdRequest(AuthConfig config) {
        super(config, AuthDefaultSource.JD);
    }

    public AuthJdRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.JD, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {

        Map<String, String> params = new HashMap<>(7);
        params.put("app_key", config.getClientId());
        params.put("app_secret", config.getClientSecret());
        params.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2_CODE, authCallback.getCode());
        String response = new HttpUtils(config.getHttpConfig()).post(source.accessToken(), params, false).getBody();
        JSONObject object = JSONObject.parseObject(response);

        this.checkResponse(object);

        return AuthToken.builder()
                .accessToken(object.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .expireIn(object.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .refreshToken(object.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .scope(object.getString(Keys.OAUTH2_SCOPE))
                .openId(object.getString("open_id"))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        UrlBuilder urlBuilder = UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2_ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("app_key", config.getClientId())
                .queryParam("method", "jingdong.user.getUserInfoByOpenId")
                .queryParam("360buy_param_json", "{\"openId\":\"" + authToken.getOpenId() + "\"}")
                .queryParam("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                .queryParam("v", "2.0");
        urlBuilder.queryParam("sign", GlobalAuthUtils.generateJdSignature(config.getClientSecret(), urlBuilder.getReadOnlyParams()));
        String response = new HttpUtils(config.getHttpConfig()).post(urlBuilder.build(true)).getBody();
        JSONObject object = JSONObject.parseObject(response);

        this.checkResponse(object);

        JSONObject data = this.getUserDataJsonObject(object);

        return AuthUser.builder()
                .rawUserInfo(data)
                .uuid(authToken.getOpenId())
                .username(data.getString("nickName"))
                .nickname(data.getString("nickName"))
                .avatar(data.getString("imageUrl"))
                .gender(AuthUserGender.getRealGender(data.getString("gendar")))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 个人用户无法申请应用
     * 暂时只能参考官网给出的返回结果解析
     *
     * @param object 请求返回结果
     * @return data JSONObject
     */
    private JSONObject getUserDataJsonObject(JSONObject object) {
        return object.getJSONObject("jingdong_user_getUserInfoByOpenId_response")
                .getJSONObject("getuserinfobyappidandopenid_result")
                .getJSONObject("data");
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        Map<String, String> params = new HashMap<>(7);
        params.put("app_key", config.getClientId());
        params.put("app_secret", config.getClientSecret());
        params.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_REFRESH_TOKEN);
        params.put(Keys.OAUTH2_REFRESH_TOKEN, oldToken.getRefreshToken());
        String response = new HttpUtils(config.getHttpConfig()).post(source.refresh(), params, false).getBody();
        JSONObject object = JSONObject.parseObject(response);

        this.checkResponse(object);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(object.getString(Keys.OAUTH2_ACCESS_TOKEN))
                        .expireIn(object.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                        .refreshToken(object.getString(Keys.OAUTH2_REFRESH_TOKEN))
                        .scope(object.getString(Keys.OAUTH2_SCOPE))
                        .openId(object.getString("open_id"))
                        .build())
                .build();
    }

    private void checkResponse(JSONObject object) {
        if (object.containsKey("error_response")) {
            throw new AuthException(object.getJSONObject("error_response").getString("zh_desc"));
        }
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam("app_key", config.getClientId())
                .queryParam(Keys.OAUTH2_RESPONSE_TYPE, Keys.OAUTH2_CODE)
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthJdScope.values())))
                .queryParam(Keys.OAUTH2_STATE, getRealState(state))
                .build();
    }

}
