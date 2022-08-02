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

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.OnRequestContent;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RegexThreatProtectionPolicy {

    private static final String BAD_REQUEST = "Bad Request";
    private static final String REGEX_THREAT_HEADER_DETECTED_KEY = "REGEX_THREAT_HEADER_DETECTED";
    private static final String REGEX_THREAT_PATH_DETECTED_KEY = "REGEX_THREAT_PATH_DETECTED";
    private static final String REGEX_THREAT_BODY_DETECTED_KEY = "REGEX_THREAT_BODY_DETECTED";

    private RegexThreatProtectionPolicyConfiguration configuration;

    public RegexThreatProtectionPolicy(RegexThreatProtectionPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {
        // Execute regex on request header.
        if (configuration.isCheckHeaders() && matches(request.headers())) {
            policyChain.failWith(
                PolicyResult.failure(REGEX_THREAT_HEADER_DETECTED_KEY, HttpStatusCode.BAD_REQUEST_400, BAD_REQUEST, MediaType.TEXT_PLAIN)
            );
            return;
        }

        // Execute regex on pathInfo and each query parameter.
        if (
            configuration.isCheckPath() &&
            (configuration.getPattern().matcher(decode(request.pathInfo())).matches() || matches(request.parameters(), true))
        ) {
            policyChain.failWith(
                PolicyResult.failure(REGEX_THREAT_PATH_DETECTED_KEY, HttpStatusCode.BAD_REQUEST_400, BAD_REQUEST, MediaType.TEXT_PLAIN)
            );
            return;
        }

        policyChain.doNext(request, response);
    }

    @OnRequestContent
    public ReadWriteStream<Buffer> onRequestContent(Request request, PolicyChain policyChain) {
        if (configuration.isCheckBody()) {
            return new BufferedReadWriteStream() {
                final Buffer buffer = Buffer.buffer();

                @Override
                public SimpleReadWriteStream<Buffer> write(Buffer content) {
                    buffer.appendBuffer(content);
                    return this;
                }

                @Override
                public void end() {
                    // Load the body in memory and execute the regex on it.
                    if (configuration.getPattern().matcher(buffer.toString()).matches()) {
                        policyChain.streamFailWith(
                            PolicyResult.failure(
                                REGEX_THREAT_BODY_DETECTED_KEY,
                                HttpStatusCode.BAD_REQUEST_400,
                                BAD_REQUEST,
                                MediaType.TEXT_PLAIN
                            )
                        );
                    } else {
                        if (buffer.length() > 0) {
                            super.write(buffer);
                        }
                        super.end();
                    }
                }
            };
        }

        return null;
    }

    private boolean matches(HttpHeaders headers) {
        return matches(headers, false);
    }

    private boolean matches(HttpHeaders headers, boolean decodeValues) {
        Pattern pattern = configuration.getPattern();

        boolean match = false;

        Iterator<String> names = headers.names().iterator();
        while (names.hasNext()) {
            String header = names.next();

            match =
                pattern.matcher(header).matches() ||
                headers.getAll(header).stream().anyMatch(e -> pattern.matcher(decodeValues ? decode(e) : e).matches());
            if (match) {
                break;
            }
        }

        return match;
    }

    private boolean matches(MultiValueMap<String, String> map) {
        return matches(map, false);
    }

    private boolean matches(MultiValueMap<String, String> map, boolean decodeValues) {
        Pattern pattern = configuration.getPattern();

        return map
            .entrySet()
            .stream()
            .anyMatch(e ->
                pattern.matcher(e.getKey()).matches() ||
                e.getValue().stream().filter(Objects::nonNull).anyMatch(v -> pattern.matcher(decodeValues ? decode(v) : v).matches())
            );
    }

    private String decode(String value) {
        try {
            return URLDecoder.decode(value, Charset.defaultCharset().name());
        } catch (UnsupportedEncodingException e) {
            return value;
        }
    }
}
