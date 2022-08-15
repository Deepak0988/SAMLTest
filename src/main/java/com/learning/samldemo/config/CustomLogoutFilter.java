package com.learning.samldemo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Configuration
@Slf4j
public class CustomLogoutFilter extends GenericFilterBean {
    private RequestMatcher logoutRequestMatcher;
    private final LogoutHandler handler;
    private final CustomLogoutSuccessHandler logoutSuccessHandler;

    public CustomLogoutFilter(CustomLogoutHandler handler, CustomLogoutSuccessHandler logoutSuccessHandler) {
        this.handler = new LogoutSuccessEventPublishingLogoutHandler();
        this.logoutSuccessHandler = logoutSuccessHandler;
        this.setFilterProcessesUrl("/logout");
    }


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (this.requiresLogout((HttpServletRequest) request, (HttpServletResponse) response)) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (this.logger.isDebugEnabled()) {
                this.logger.debug(LogMessage.format("Logging out [%s]", auth));
            }
            this.handler.logout((HttpServletRequest) request, (HttpServletResponse) response, auth);
            this.logoutSuccessHandler.onLogoutSuccess((HttpServletRequest) request, (HttpServletResponse) response, auth);
        } else {
            chain.doFilter(request, response);
        }
    }

    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        if (this.logoutRequestMatcher.matches(request)) {
            return true;
        } else {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Did not match request to %s", this.logoutRequestMatcher));
            }

            return false;
        }
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.logoutRequestMatcher = new AntPathRequestMatcher(filterProcessesUrl);
    }
}
