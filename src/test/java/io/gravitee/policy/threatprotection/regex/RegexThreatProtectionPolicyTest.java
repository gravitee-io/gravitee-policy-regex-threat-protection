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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;

public class RegexThreatProtectionPolicyTest {

    private static final String EVIL_REGEX = ".*evil.*";
    private static final String SQL_INJECTION_REGEX = ".*[\\s]*((delete)|(exec)|(drop\\s*table)|(insert)|(shutdown)|(update)|(\\bor\\b)).*";
    private static final String XSS_REGEX = ".*<\\s*script\\b[^>]*>[^<]+<\\s*/\\s*script\\s*>.*";
    private static final String PATH_TRAVERSAL_REGEX = "^\\/?(.*\\.\\.).*$";

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    private RegexThreatProtectionPolicyConfiguration configuration;
    private RegexThreatProtectionPolicy cut;

    @BeforeEach
    public void setUp() {
        configuration = new RegexThreatProtectionPolicyConfiguration();
        configuration.setCheckHeaders(false);
        configuration.setCheckPath(false);
        configuration.setCheckBody(false);

        policyChain = mock(PolicyChain.class);
        request = mock(Request.class);
        response = mock(Response.class);

        cut = new RegexThreatProtectionPolicy(configuration);
    }

    static Stream<Arguments> provideTestCases() {
        return Stream.of(
            Arguments.of("shouldNotRejectWhenNoCheck", false, false, false, true, null, EVIL_REGEX, true),
            Arguments.of("shouldRejectEvilHeaderName", true, false, false, true, "header-evil:jkl", EVIL_REGEX, false),
            Arguments.of("shouldRejectEvilHeaderValue", true, false, false, true, "header2:jkl-evil", EVIL_REGEX, false),
            Arguments.of("shouldRejectEvilPath", false, true, false, true, "/path-evil", EVIL_REGEX, false),
            Arguments.of("shouldRejectEvilParamName", false, true, false, true, "param-evil:jkl", EVIL_REGEX, false),
            Arguments.of("shouldRejectEvilParamValue", false, true, false, true, "param2:jkl-evil", EVIL_REGEX, false),
            Arguments.of("shouldRejectEvilBody", false, false, true, true, "evil body content", EVIL_REGEX, false),
            Arguments.of(
                "shouldRejectEvilMultiLineSQLInjection",
                false,
                false,
                true,
                false,
                "Hello,\nDROP\nTABLE users; Goodbye!",
                SQL_INJECTION_REGEX,
                false
            ),
            Arguments.of(
                "shouldAcceptEvilMultiLineSQLInjectionWhenFullMatchingIsEnabled",
                false,
                false,
                true,
                true,
                "Hello,\nDROP\nTABLE users; \nGoodbye!",
                SQL_INJECTION_REGEX,
                true
            ),
            Arguments.of(
                "shouldRejectEvilMultiLineXSS",
                false,
                false,
                true,
                false,
                "<html>\n<script>\nalert('XSS');\n</script>\n</html>",
                XSS_REGEX,
                false
            ),
            Arguments.of("shouldNotRejectMultiLineSafeInput", false, false, true, false, "Hello,\nThis is safe content.", XSS_REGEX, true),
            Arguments.of("shouldRejectPathTraversal", false, true, false, true, "/path/../secret", PATH_TRAVERSAL_REGEX, false)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("provideTestCases")
    public void testRegexProtection(
        String testName,
        boolean checkHeaders,
        boolean checkPath,
        boolean checkBody,
        boolean fullMatching,
        String input,
        String regex,
        boolean shouldPass
    ) {
        configuration.setCheckHeaders(checkHeaders);
        configuration.setCheckPath(checkPath);
        configuration.setCheckBody(checkBody);
        configuration.setFullMatching(fullMatching);
        configuration.setRegex(regex);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        if (checkHeaders) {
            when(request.headers()).thenReturn(createHttpHeaders(input));
        }
        if (checkPath) {
            when(request.pathInfo()).thenReturn(input);
        }
        if (checkBody) {
            assertThat(readWriteStream).isNotNull();
            final AtomicBoolean endCalled = spyEndHandler(readWriteStream);
            readWriteStream.write(Buffer.buffer(input));
            readWriteStream.end();
            assertThat(endCalled.get()).isEqualTo(shouldPass);
            if (!shouldPass) {
                verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
            } else {
                verifyNoInteractions(policyChain);
            }
        } else {
            cut.onRequest(request, response, policyChain);
            if (!shouldPass) {
                verify(policyChain, times(1)).failWith(any(PolicyResult.class));
            } else {
                verify(policyChain, times(1)).doNext(request, response);
            }
        }
    }

    private HttpHeaders createHttpHeaders(String input) {
        HttpHeaders headers = HttpHeaders.create();
        if (input != null) {
            String[] parts = input.split(":");
            if (parts.length == 2) {
                headers.add(parts[0], parts[1]);
            }
        }
        return headers;
    }

    private AtomicBoolean spyEndHandler(ReadWriteStream<?> readWriteStream) {
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = new AtomicBoolean(false);
        readWriteStream.endHandler(__ -> hasCalledEndOnReadWriteStreamParentClass.set(true));
        return hasCalledEndOnReadWriteStreamParentClass;
    }
}
