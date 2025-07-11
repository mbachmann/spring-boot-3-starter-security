
package com.example.starter.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * CORS configuration: CORS must be processed before Spring Security because the pre-flight request will not contain any cookies. Therefore, the request would determine the user is not authenticated
 * and reject it.
 */
@Configuration
public class CorsConfig {

    @Value("${endpoints.web.cors.path-mappings}")
    private String pathMappings;
    @Value("${endpoints.web.cors.allowed-origins}")
    private List<String> allowedOrigins;
    @Value("${endpoints.web.cors.allowed-methods}")
    private List<String> allowedMethods;
    @Value("${endpoints.web.cors.allowed-headers}")
    private List<String> allowedHeaders;

    /* @Bean
    CorsConfigurationSource corsConfigurationSource()  {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(allowedMethods);
        configuration.setAllowedHeaders(allowedHeaders);
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(pathMappings, configuration);
        return source;
    } */

    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(allowedMethods);
        config.setAllowedHeaders(allowedHeaders);
        config.setAllowCredentials(true);
        config.setMaxAge(60L);
        source.registerCorsConfiguration(pathMappings, config);
        return new CorsFilter(source);
    }
}
