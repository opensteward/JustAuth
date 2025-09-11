package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * 爱发电
 *
 * @author handy
 */
public class AuthAfDianRequest extends AuthDefaultRequest {

    public AuthAfDianRequest(AuthConfig config) {
        super(config, AuthDefaultSource.AFDIAN);
    }

    public AuthAfDianRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.AFDIAN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> params = new HashMap<>();
        params.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2_CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2_CODE, authCallback.getCode());
        params.put(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri());
        String response = new HttpUtils(config.getHttpConfig()).post(AuthDefaultSource.AFDIAN.accessToken(), params, false).getBody();
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        String userId = accessTokenObject.getJSONObject(Keys.DATA).getString("user_id");
        return AuthToken.builder().userId(userId).build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        return AuthUser.builder()
                .uuid(authToken.getUserId())
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2_RESPONSE_TYPE, Keys.OAUTH2_CODE)
                .queryParam(Keys.OAUTH2_SCOPE, "basic")
                .queryParam(Keys.OAUTH2_CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2_STATE, getRealState(state))
                .build();
    }

}
