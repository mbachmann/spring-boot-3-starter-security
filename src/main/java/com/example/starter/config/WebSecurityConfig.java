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
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors().and()  // uncomment this line with CorsConfigurationSource, comment this line with CorsFilter
            // for h2-console
            .headers().frameOptions().disable().and()
            .csrf(AbstractHttpConfigurer::disable)
            //.csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
            .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeHttpRequests((requests) -> requests
                .requestMatchers(OPTIONS).permitAll()
                .requestMatchers(antMatcher(HttpMethod.POST, "/api/auth/**")).permitAll()
                .requestMatchers(antMatcher(HttpMethod.POST, "/api/test/**")).permitAll()
                .requestMatchers(antMatcher(HttpMethod.GET, "/api/auth/**")).permitAll()
                .requestMatchers(antMatcher(HttpMethod.GET, "/api/test/**")).permitAll()
                .requestMatchers(antMatcher(HttpMethod.GET, "/actuator/**")).permitAll()
                .requestMatchers(
                    antMatcher(HttpMethod.GET, "/error"),
                    antMatcher( "/h2-console/**"),
                    antMatcher("/index.html"),
                    antMatcher(HttpMethod.GET, "/favicon.ico"),
                    // regexMatcher(".*\\?x=y")).hasRole("SPECIAL"),
                    // antMatcher(HttpMethod.POST, "/user/**")).hasRole("ADMIN"),
                    antMatcher(HttpMethod.GET, "/v3/**"),
                    antMatcher(HttpMethod.GET, "/swagger-ui.html"),
                    antMatcher(HttpMethod.GET, "/swagger-ui/**")).permitAll()
                .anyRequest()
                .authenticated()
            );
        http.headers(headers -> headers.frameOptions().sameOrigin());
        http.authenticationProvider(authenticationProvider());

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    /*@Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(new AntPathRequestMatcher("/static/**"), new AntPathRequestMatcher("/resources/**"));
    }*/
}