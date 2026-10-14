package com.credintel.auth_service.config;

import com.credintel.request.ApiPatternConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.DispatcherServlet;

import java.util.List;

@Configuration
public class ServletConfig {

    @Autowired
    DispatcherServlet dispatcherServlet;

    @Bean
    public ServletRegistrationBean<DispatcherServlet> servicesDispatcherServlet(){
        ServletRegistrationBean<DispatcherServlet> registrationBean = new ServletRegistrationBean<>(dispatcherServlet);
        registrationBean.setUrlMappings(List.of(ApiPatternConstants.SERVICES));
        registrationBean.setName("AUTH-SERVICES");
        registrationBean.setLoadOnStartup(1);
        return registrationBean;
    }

    @Bean
    public ServletRegistrationBean<DispatcherServlet> ApiDispatcherServlet(){
        ServletRegistrationBean<DispatcherServlet> registrationBean = new ServletRegistrationBean<>(dispatcherServlet);
        registrationBean.setUrlMappings(List.of(ApiPatternConstants.API, ApiPatternConstants.API_PATTERN));
        registrationBean.setName("AUTH-API");
        registrationBean.setLoadOnStartup(1);
        return registrationBean;
    }


}
