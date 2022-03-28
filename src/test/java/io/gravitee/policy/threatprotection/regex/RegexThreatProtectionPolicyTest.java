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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.gravitee.common.util.LinkedMultiValueMap;
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
import java.util.concurrent.atomic.AtomicBoolean;
import org.assertj.core.api.Assertions;
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

        assertThat(readWriteStream).isNull();
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

        assertThat(readWriteStream).isNull();
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

        assertThat(readWriteStream).isNull();

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

        assertThat(readWriteStream).isNull();
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

        assertThat(readWriteStream).isNull();
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

        assertThat(readWriteStream).isNull();
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

        assertThat(readWriteStream).isNull();
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

        assertThat(readWriteStream).isNull();
        verify(request, times(0)).headers();
        verify(request, times(1)).pathInfo();
        verify(request, times(1)).parameters();
        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldIgnoreBody() {
        configuration.setCheckBody(false);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertThat(readWriteStream).isNull();

        verifyZeroInteractions(policyChain);
    }

    @Test
    public void shouldCheckAndAcceptBody() {
        configuration.setCheckBody(true);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("body content"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isTrue();

        verifyZeroInteractions(policyChain);
    }

    @Test
    public void shouldRejectEvilBody() {
        configuration.setCheckBody(true);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("evil body content"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectEvilBodyCaseInsensitive() {
        configuration.setCheckBody(true);

        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);
        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("EvIL body content"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    private HttpHeaders createHttpHeaders() {
        HttpHeaders headers = HttpHeaders.create();
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

    /**
     * Replace the endHandler of the resulting ReadWriteStream of the policy execution.
     * This endHandler will set an {@link AtomicBoolean} to {@code true} if its called.
     * It will allow us to verify if super.end() has been called on {@link BufferedReadWriteStream#end()}
     * @param readWriteStream: the {@link ReadWriteStream} to modify
     * @return an AtomicBoolean set to {@code true} if {@link SimpleReadWriteStream#end()}, else {@code false}
     */
    private AtomicBoolean spyEndHandler(ReadWriteStream readWriteStream) {
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = new AtomicBoolean(false);
        readWriteStream.endHandler(__ -> {
            hasCalledEndOnReadWriteStreamParentClass.set(true);
        });
        return hasCalledEndOnReadWriteStreamParentClass;
    }
}
