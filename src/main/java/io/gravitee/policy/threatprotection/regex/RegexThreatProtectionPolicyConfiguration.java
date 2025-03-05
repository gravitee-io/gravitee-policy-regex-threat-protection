/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.threatprotection.regex;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.policy.api.PolicyConfiguration;
import java.util.regex.Pattern;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RegexThreatProtectionPolicyConfiguration implements PolicyConfiguration {

    /**
     * Compiled version of regex.
     */
    @JsonIgnore
    private Pattern pattern;

    /**
     * The regex to use.
     */
    private String regex;

    /**
     * Flag indicating if headers must be checked against the regex.
     * Default true.
     */
    private boolean checkHeaders = true;

    /**
     * Flag indicating if path must be checked against the regex.
     * Default true.
     */
    private boolean checkPath = true;

    /**
     * Flag indicating if body must be checked against the regex.
     * Default true.
     */
    private boolean checkBody = true;

    /**
     * Flag indicating if matching is case sensitive or not.
     * Default is false (case insensitive).
     */
    private boolean caseSensitive = false;

    /**
     * Flag indicating if matching is full or not.
     * Default is true (fullMatching).
     */
    private boolean fullMatching = true;

    /**
     * Returns the compiled version of the regex.
     *
     * @return the compiled regex.
     */
    public Pattern getPattern() {
        if (pattern == null) {
            int flags = 0;

            if (!caseSensitive) {
                flags = flags | Pattern.CASE_INSENSITIVE;
            }

            pattern = Pattern.compile(regex, flags);
        }

        return pattern;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    public boolean isCheckHeaders() {
        return checkHeaders;
    }

    public void setCheckHeaders(boolean checkHeaders) {
        this.checkHeaders = checkHeaders;
    }

    public boolean isCheckPath() {
        return checkPath;
    }

    public void setCheckPath(boolean checkPath) {
        this.checkPath = checkPath;
    }

    public boolean isCheckBody() {
        return checkBody;
    }

    public void setCheckBody(boolean checkBody) {
        this.checkBody = checkBody;
    }

    public boolean isCaseSensitive() {
        return caseSensitive;
    }

    public void setCaseSensitive(boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }

    public boolean isFullMatching() {
        return fullMatching;
    }

    public void setFullMatching(boolean fullMatching) {
        this.fullMatching = fullMatching;
    }
}
