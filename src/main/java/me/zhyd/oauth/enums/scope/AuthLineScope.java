package me.zhyd.oauth.enums.scope;

import lombok.AllArgsConstructor;
import lombok.Getter;
import me.zhyd.oauth.constant.Keys;

/**
 * Line 平台 OAuth 授权范围
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.0
 */
@Getter
@AllArgsConstructor
public enum AuthLineScope implements AuthScope {

    /**
     * {@code scope} 含义，以{@code description} 为准
     */

    PROFILE(Keys.OAUTH2_SCOPE__PROFILE, "Get profile details", true),
    OPENID(Keys.OAUTH2_SCOPE__OPENID, "Get id token", true),
    EMAIL(Keys.OAUTH2_SCOPE__EMAIL, "Get email (separate authorization required)", false);

    private final String scope;
    private final String description;
    private final boolean isDefault;

}
