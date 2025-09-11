package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.scope.AuthWeChatEnterpriseWebScope;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.UrlBuilder;

/**
 * <p>
 * 企业微信网页登录
 * </p>
 *
 * @author liguanhua (347826496(a)qq.com)
 * @since 1.15.9
 */
public class AuthWeChatEnterpriseWebRequest extends AbstractAuthWeChatEnterpriseRequest {
    public AuthWeChatEnterpriseWebRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_WEB);
    }

    public AuthWeChatEnterpriseWebRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WECHAT_ENTERPRISE_WEB, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam("appid", config.getClientId())
                .queryParam("agentid", config.getAgentId())
                .queryParam("redirect_uri", GlobalAuthUtils.urlEncode(config.getRedirectUri()))
                .queryParam(Keys.OAUTH2_RESPONSE_TYPE, Keys.OAUTH2_CODE)
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthWeChatEnterpriseWebScope.values())))
                .queryParam("state", getRealState(state).concat("#wechat_redirect"))
                .build();
    }
}
