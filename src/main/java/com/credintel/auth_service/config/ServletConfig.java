package com.credintel.auth_service.config;

import org.springframework.boot.webmvc.autoconfigure.DispatcherServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.DispatcherServlet;

@Configuration
public class ServletConfig {

    /**
     * The ONLY mapping of the DispatcherServlet: /api/v1 (e.g. /auth-service/api/v1/auth/login).
     * The bean name replaces Spring Boot's default "/" registration; previously every endpoint was
     * also reachable at "/", "/api/v1/services/*", which made gateway rules easy to bypass.
     */
    @Bean(name = "dispatcherServletRegistration")
    public DispatcherServletRegistrationBean apiDispatcherServlet(DispatcherServlet dispatcherServlet) {
        DispatcherServletRegistrationBean registrationBean =
                new DispatcherServletRegistrationBean(dispatcherServlet, "/api/v1");
        registrationBean.setName("AUTH-API");
        registrationBean.setLoadOnStartup(1);
        return registrationBean;
    }
}
