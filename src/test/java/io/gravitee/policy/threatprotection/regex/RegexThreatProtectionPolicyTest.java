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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.*;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.threatprotection.regex.RegexThreatProtectionPolicy;
import io.gravitee.policy.threatprotection.regex.RegexThreatProtectionPolicyConfiguration;
import io.gravitee.reporter.api.http.Metrics;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class RegexThreatProtectionPolicyTest {

    private static final String EVIL_REGEX = ".*evil.*";

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    RegexThreatProtectionPolicyConfiguration configuration;

    private RegexThreatProtectionPolicy cut;

    @Before
    public void before() {
        configuration = new RegexThreatProtectionPolicyConfiguration();
        configuration.setRegex(EVIL_REGEX);
        configuration.setCheckHeaders(false);
        configuration.setCheckPath(false);
        configuration.setCheckBody(false);

        cut = new RegexThreatProtectionPolicy(configuration);
    }

    @Test
    public void shouldAcceptAllWhenNoCheck() {
        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(0)).headers();
        verify(request, times(0)).pathInfo();
        verify(request, times(0)).parameters();
        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void shouldCheckAndAcceptHeaders() {
        when(request.headers()).thenReturn(createHttpHeaders());
        configuration.setCheckHeaders(true);

        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(1)).headers();
        verify(request, times(0)).pathInfo();
        verify(request, times(0)).parameters();
        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void shouldRejectEvilHeaderName() {
        HttpHeaders headers = createHttpHeaders();
        headers.add("header-evil", "jkl");

        when(request.headers()).thenReturn(headers);
        configuration.setCheckHeaders(true);

        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(1)).headers();
        verify(request, times(0)).pathInfo();
        verify(request, times(0)).parameters();
        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectEvilHeaderValue() {
        HttpHeaders headers = createHttpHeaders();
        headers.add("header2", "jkl-evil");

        when(request.headers()).thenReturn(headers);
        configuration.setCheckHeaders(true);

        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(1)).headers();
        verify(request, times(0)).pathInfo();
        verify(request, times(0)).parameters();
        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldCheckAndAcceptPathAndParams() {
        when(request.pathInfo()).thenReturn("/path");
        when(request.parameters()).thenReturn(createParams());
        configuration.setCheckPath(true);

        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(0)).headers();
        verify(request, times(1)).pathInfo();
        verify(request, times(1)).parameters();
        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void shouldRejectEvilPath() {
        when(request.pathInfo()).thenReturn("/path-evil");
        configuration.setCheckPath(true);

        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(0)).headers();
        verify(request, times(1)).pathInfo();
        verify(request, times(0)).parameters();
        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectEvilParamName() {
        MultiValueMap<String, String> params = createParams();
        params.add("param-evil", "jkl");

        when(request.pathInfo()).thenReturn("/path");
        when(request.parameters()).thenReturn(params);
        configuration.setCheckPath(true);

        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(0)).headers();
        verify(request, times(1)).pathInfo();
        verify(request, times(1)).parameters();
        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectEvilParamValue() {
        MultiValueMap<String, String> params = createParams();
        params.add("param2", "jkl-evil");

        when(request.pathInfo()).thenReturn("/path");
        when(request.parameters()).thenReturn(params);
        configuration.setCheckPath(true);

        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);
        cut.onRequest(request, response, policyChain);

        assertNull(readWriteStream);
        verify(request, times(0)).headers();
        verify(request, times(1)).pathInfo();
        verify(request, times(1)).parameters();
        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldIgnoreBody() {
        configuration.setCheckBody(false);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertNull(readWriteStream);

        verifyZeroInteractions(policyChain);
    }

    @Test
    public void shouldCheckAndAcceptBody() {
        when(request.headers()).thenReturn(createHttpHeaders());
        configuration.setCheckBody(true);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertNotNull(readWriteStream);

        readWriteStream.write(Buffer.buffer("body content"));
        readWriteStream.end();

        verifyZeroInteractions(policyChain);
    }

    @Test
    public void shouldRejectEvilBody() {
        when(request.headers()).thenReturn(createHttpHeaders());
        configuration.setCheckBody(true);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertNotNull(readWriteStream);

        readWriteStream.write(Buffer.buffer("evil body content"));
        readWriteStream.end();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectEvilBodyCaseInsensitive() {
        when(request.headers()).thenReturn(createHttpHeaders());
        configuration.setCheckBody(true);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertNotNull(readWriteStream);

        readWriteStream.write(Buffer.buffer("EvIL body content"));
        readWriteStream.end();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    private HttpHeaders createHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("header1", "abc");
        headers.add("header1", "def");
        headers.add("header2", "ghi");
        headers.add("header2", "jkl");
        return headers;
    }

    private MultiValueMap<String, String> createParams() {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("param1", "abc");
        params.add("param1", "def");
        params.add("param2", "ghi");
        params.add("param2", "jkl");
        return params;
    }
}
