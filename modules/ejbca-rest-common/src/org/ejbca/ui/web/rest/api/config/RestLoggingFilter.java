/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.log4j.Logger;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;

/**
 * Servlet Filter for logging REST request and responses.
 */
public class RestLoggingFilter implements Filter {

    /** Helper class for making a copy of a ServletOutputStream */
    private static class CopyingServletOutputStream extends ServletOutputStream {

        private final ServletOutputStream servletOutputStream;
        private final ByteArrayOutputStream baos;

        private CopyingServletOutputStream(final ServletOutputStream servletOutputStream, final ByteArrayOutputStream baos) {
            this.servletOutputStream = servletOutputStream;
            this.baos = baos;
        }
        
        @Override
        public void write(int b) throws IOException {
            this.baos.write(b);
            this.servletOutputStream.write(b);
        }
        
        @Override
        public void flush() throws IOException {
            this.servletOutputStream.flush();
        }

        @Override
        public void close() throws IOException {
            this.servletOutputStream.close();
        }

        @Override
        public boolean isReady() {
            return this.servletOutputStream.isReady();
        }

        @Override
        public void setWriteListener(final WriteListener writeListener) {
            this.servletOutputStream.setWriteListener(writeListener);            
        }       
    }
    
    /** Helper class for making a copy of a ServletInputStream */
    private static final class CopyingServletInputStream extends ServletInputStream {

        private final ServletInputStream servletInputStream;
        private final ByteArrayOutputStream baos;

        private CopyingServletInputStream(final ServletInputStream servletInputStream, final ByteArrayOutputStream baos) {
            this.servletInputStream = servletInputStream;
            this.baos = baos;
        }

        @Override
        public int available() throws IOException {
            return this.servletInputStream.available();
        }

        @Override
        public int read() throws IOException {
            final int b = this.servletInputStream.read();
            if (b>0) {
                baos.write(b);
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            final int count = this.servletInputStream.read(buf, off, len);
            if (count>0) {
                baos.write(buf, off, count);
            }
            return count;
        }

        @Override
        public void close() throws IOException {
            this.servletInputStream.close();
        }

        @Override
        public boolean isFinished() {
            return this.servletInputStream.isFinished();
        }

        @Override
        public boolean isReady() {
            return this.servletInputStream.isReady();
        }

        @Override
        public void setReadListener(final ReadListener readListener) {
            this.servletInputStream.setReadListener(readListener);
        }       
    }
    
    private static final Logger log = Logger.getLogger(RestLoggingFilter.class);

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {        
        final long startTime = System.currentTimeMillis();
        final HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        final StringBuilder sbInfo = new StringBuilder(200);
        sbInfo.append(httpServletRequest.getMethod() + " " + httpServletRequest.getRequestURL().toString() + " received from " + servletRequest.getRemoteAddr());
        sbInfo.append("  X-Forwarded-For: " + httpServletRequest.getHeader("X-Forwarded-For"));
        log.info(sbInfo.toString());
        
        if (log.isTraceEnabled()) {
            final StringBuilder sb = new StringBuilder(200);
            sb.append(sbInfo);
            sb.append("\nRequest headers:\n");
            final Enumeration<String> requestHeaderNames = httpServletRequest.getHeaderNames();
            while (requestHeaderNames.hasMoreElements()) {
                final String headerName = requestHeaderNames.nextElement();
                final Enumeration<String> headers = httpServletRequest.getHeaders(headerName);
                while (headers.hasMoreElements()) {
                    final String headerValue = headers.nextElement();
                    sb.append("  " + headerName + ": " + headerValue + "\n");
                }
            }
            final ByteArrayOutputStream requestBaos = new ByteArrayOutputStream();
            final HttpServletRequestWrapper httpServletRequestWrapper = new HttpServletRequestWrapper(httpServletRequest) {
                private final CopyingServletInputStream copyingServletInputStream = new CopyingServletInputStream(servletRequest.getInputStream(), requestBaos);
                @Override
                public ServletInputStream getInputStream() throws IOException {
                    return copyingServletInputStream;
                }
            };
            final ByteArrayOutputStream responseBaos = new ByteArrayOutputStream();
            final HttpServletResponseWrapper httpServletResponseWrapper = new HttpServletResponseWrapper((HttpServletResponse) servletResponse) {
                private final CopyingServletOutputStream copyingServletOutputStream = new CopyingServletOutputStream(super.getOutputStream(), responseBaos);
                @Override
                public ServletOutputStream getOutputStream() {
                    return copyingServletOutputStream;
                }            
            };
            
            filterChain.doFilter(httpServletRequestWrapper, httpServletResponseWrapper);
            
            String url = httpServletRequest.getRequestURL().toString();
            boolean logRequestAndResponseBody = true;
            if(LogRedactionUtils.redactPii() && // RA
                    (url.contains(AvailableProtocols.REST_ENDENTITY_MANAGEMENT.getUrl()) ||
                     url.contains(AvailableProtocols.REST_ENDENTITY_MANAGEMENT_V2.getUrl()) ||
                     url.contains(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT.getUrl()) ||
                     url.contains(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT_V2.getUrl()) ||
                     url.contains(AvailableProtocols.REST_SSH_V1.getUrl()))) {
                logRequestAndResponseBody = false;
            }
            
            if (logRequestAndResponseBody) {
                sb.append("Request data:\n");
                final String requestData = new String(requestBaos.toByteArray(), StandardCharsets.UTF_8);
                sb.append("  ").append(requestData).append("\n");
                
                
                final String responseData = new String(responseBaos.toByteArray(), StandardCharsets.UTF_8);
                sb.append("Response data:\n");
                sb.append(responseData).append("\n");
            } else {
                sb.append("Request and response data is redacted.\n");
            }
            
            final long endTime = System.currentTimeMillis();
            sb.append("Time taken: ").append(endTime-startTime).append("ms").append("\n");;
            
            log.trace(sb.toString());
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
}
