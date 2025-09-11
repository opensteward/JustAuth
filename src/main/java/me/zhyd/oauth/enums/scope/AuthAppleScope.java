package me.zhyd.oauth.enums.scope;

import lombok.AllArgsConstructor;
import lombok.Getter;
import me.zhyd.oauth.constant.Keys;

/**
 * @see <a href="https://developer.apple.com/documentation/sign_in_with_apple/clientconfigi/3230955-scope/">scope</a>
 */
@Getter
@AllArgsConstructor
public enum AuthAppleScope implements AuthScope {
    EMAIL(Keys.OAUTH2_SCOPE__EMAIL, "用户邮箱", true),
    NAME(Keys.NAME, "用户名", true),
    ;

    private final String scope;
    private final String description;
    private final boolean isDefault;
}
