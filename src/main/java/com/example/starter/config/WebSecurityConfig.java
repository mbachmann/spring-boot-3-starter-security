package com.example.starter.config;

import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import com.example.starter.security.AuthEntryPointJwt;
import com.example.starter.security.AuthTokenFilter;

import com.example.starter.security.JwtUtils;
import com.example.starter.service.UserDetailsServiceImpl;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Slf4j
@AllArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
    // securedEnabled = true,
    // jsr250Enabled = true,
    prePostEnabled = true)
public class WebSecurityConfig {

    private UserDetailsServiceImpl userDetailsService;

    private AuthEntryPointJwt unauthorizedHandler;

    private JwtUtils jwtUtils;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter(jwtUtils, userDetailsService);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(0)
    SecurityFilterChain resources(HttpSecurity http) throws Exception {
        String[] permittedResources = new String[] {
            "/", "/static/**","/css/**","/js/**","/webfonts/**", "/webjars/**",
            "/index.html","/favicon.ico", "/error",
            "/v3/**","/swagger-ui.html","/swagger-ui/**"
        };
        http
            .securityMatcher(permittedResources)
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll())
            .requestCache().disable()
            .securityContext().disable()
            .sessionManagement().disable();

        return http.build();
    }
    @Bean
    @Order(1)
    public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {
        http
            .cors().and()  // uncomment this line with CorsConfigurationSource, comment this line with CorsFilter
            .headers().frameOptions().disable().and()
            .csrf(AbstractHttpConfigurer::disable)
            .securityMatcher("/api/**")
            .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeHttpRequests((requests) -> requests
                .requestMatchers(OPTIONS).permitAll()
                .requestMatchers(antMatcher("/api/auth/**")).permitAll()
                .requestMatchers(antMatcher("/api/test/**")).permitAll()
                .requestMatchers(antMatcher(HttpMethod.GET, "/actuator/**")).permitAll()
                .requestMatchers(
                    antMatcher( "/h2-console/**")).permitAll()
            ).authenticationProvider(authenticationProvider())
            .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    /*@Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(new AntPathRequestMatcher("/static/**"), new AntPathRequestMatcher("/resources/**"));
    }*/
}