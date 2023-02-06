package com.example.starter.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile("dev")
@Configuration
public class OpenApi30Config {

    private final String moduleName;
    private final String apiVersion;

    public OpenApi30Config(
            @Value("${spring.application.name}") String moduleName,
            @Value("${springdoc.version}") String apiVersion) {
        this.moduleName = moduleName;
        this.apiVersion = apiVersion;
    }

    @Profile("dev")
    @Bean
    public OpenAPI customOpenAPI(@Value("${app.server}") String contextPath) {
        final String securitySchemeName = "bearerAuth";
        final String apiTitle = String.format("%s API", StringUtils.capitalize(moduleName));
        return new OpenAPI()
                .addServersItem(new Server().url(contextPath))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(
                        new Components()
                                //HTTP Basic, see: https://swagger.io/docs/specification/authentication/basic-authentication/
                                .addSecuritySchemes("basicScheme", new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("basic")
                                )
                                .addSecuritySchemes(securitySchemeName,
                                        new SecurityScheme()
                                                .name(securitySchemeName)
                                                .type(SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .bearerFormat("JWT")
                                )
                                //OAuth 2.0, see: https://swagger.io/docs/specification/authentication/oauth2/
                                .addSecuritySchemes("oAuthScheme", new SecurityScheme()
                                        .type(SecurityScheme.Type.OAUTH2)
                                        .description("This API uses OAuth 2 with the implicit grant flow. [More info](https://api.example.com/docs/auth)")
                                        .flows(new OAuthFlows()
                                                .implicit(new OAuthFlow()
                                                        .authorizationUrl("https://api.example.com/oauth2/authorize")
                                                        .scopes(new Scopes()
                                                                .addString("read_employees", "read your employees")
                                                                .addString("write_employees", "modify emloyees in your account")
                                                        )
                                                )
                                        )
                                )
                )
                .addSecurityItem(new SecurityRequirement()
                        .addList("basicScheme").addList("apiKeyScheme")
                )
                .addSecurityItem(new SecurityRequirement()
                        .addList("oAuthScheme")
                )
                .info(new Info().title(apiTitle).version(apiVersion));
    }
}
