package com.ericsson.eiffel.remrem.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Profile("!integration-test")
@Configuration
@EnableWebSecurity
@PropertySources({ @PropertySource("classpath:config.properties"),
        @PropertySource(value = "file:${user.home}/config.properties", ignoreResourceNotFound = true) })
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${activedirectory.enabled}")
    private boolean securityEnabled;

    @Value("${activedirectory.ldapUrl}")
    private String ldapUrl;

    @Value("${activedirectory.ldapPassword}")
    private String ldapPassword;

    @Value("${activedirectory.managerDn}")
    private String managerDn;

    @Value("${activedirectory.userSearchFilter}")
    private String userSearchFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.ldapAuthentication().userSearchFilter(userSearchFilter).contextSource().managerDn(managerDn)
                .managerPassword(ldapPassword).url(ldapUrl);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (securityEnabled) {
            http.authorizeRequests().anyRequest().authenticated().and().httpBasic().and().csrf().disable();
        } else {
            http.authorizeRequests().anyRequest().permitAll().and().csrf().disable();
        }

    }
}
