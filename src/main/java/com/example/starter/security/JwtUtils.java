package com.example.starter.security;


import com.example.starter.service.UserDetailsImpl;
import com.example.starter.utils.HasLogger;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;


@Component
@Slf4j
public class JwtUtils implements HasLogger {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${app.jwtCookieName}")
    private String jwtCookie;

    public String getJwtFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    public String getJwtFromCookies(ServerHttpRequest request) {
        HttpCookie cookie = request.getCookies().getFirst(jwtCookie);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        String jwt = generateTokenFromUsername(userPrincipal);
        return ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();

    }

    public ResponseCookie generateJwtCookie(String username, List<String> roles) {
        String jwt = generateTokenFromUsername(username, roles);
        return ResponseCookie.from(jwtCookie, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();
    }

    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from(jwtCookie, null).path("/api").build();
    }

    public String getUserNameFromJwtToken(String token) {
        SecretKey secret = Keys.hmacShaKeyFor(jwtSecret.trim().getBytes());
        return Jwts.parser().verifyWith(secret).build().parseSignedClaims(token.trim()).getPayload().getSubject();
    }

    public String generateBearerToken(UserDetailsImpl userPrincipal) {
        String bearer = generateTokenFromUsername(userPrincipal);
        return "Bearer " + bearer;
    }

    public String generateJwtToken(UserDetailsImpl userPrincipal) {
        return generateTokenFromUsername(userPrincipal);

    }
    public String generateTokenFromUsername(UserDetailsImpl userDetails) {

        SecretKey secret = Keys.hmacShaKeyFor(jwtSecret.trim().getBytes());

        String jwt = Jwts.builder()
                .header().keyId("shared")

                .and()

                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .claim("roles", userDetails.getAuthorities())
                .signWith(secret)
                .compact();
        return jwt;
}

    /**
     * Validate the Token first from the Authorization Header, if not present, then from the Cookie
     * @param request Servlet Request
     * @return boolean true if validated, false if not
     */
    public boolean validateJwtToken(HttpServletRequest request) {

        String bearerToken = request.getHeader("Authorization");
        try {
            if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
                String jwt = bearerToken.substring("Bearer ".trim().length());
                if (jwt != null && !jwt.isEmpty() && validateJwtToken(jwt)) {
                    return true;
                }
            } else {
                String jwt = getJwtFromCookies(request);
                if (jwt != null && !jwt.isEmpty() && validateJwtToken(jwt)) {
                    return true;
                }
            }
        } catch (Exception e) {
            getLogger().error("Cannot set user authentication: {}", e.getLocalizedMessage());
        }
        return false;
    }



    public boolean validateJwtToken(String authToken) {
        try {

            SecretKey secret = Keys.hmacShaKeyFor(jwtSecret.trim().getBytes());
            Jwts.parser().verifyWith(secret).build().parseSignedClaims(authToken.trim());

            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }


    public String generateTokenFromUsername(String username, List<String> roles) {

        SecretKey secret = Keys.hmacShaKeyFor(jwtSecret.trim().getBytes());

        String jwt = Jwts.builder()
                .header().keyId("shared")

                .and()

                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .claim("roles", roles)
                .signWith(secret)
                .compact();
        return jwt;
    }
}
