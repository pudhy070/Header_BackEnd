package com.security.test1.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    private SecretKey getSigningKey() {
        String actualSecret = secret.length() >= 32 ? secret :
                secret + "additionalSecretToMakeItLongEnough123456";
        return Keys.hmacShaKeyFor(actualSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String email, String name, String picture) {
        try {
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + expiration);

            Map<String, Object> claims = new HashMap<>();
            claims.put("email", email);
            claims.put("name", name);
            claims.put("picture", picture);
            claims.put("iat", now.getTime() / 1000);
            claims.put("exp", expiryDate.getTime() / 1000);

            String token = Jwts.builder()
                    .setClaims(claims)
                    .setSubject(email)
                    .setIssuedAt(now)
                    .setExpiration(expiryDate)
                    .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                    .compact();

            log.info("JWT 토큰 생성 성공 - email: {}, name: {}", email, name);
            return token;

        } catch (Exception e) {
            log.error("JWT 토큰 생성 실패", e);
            throw new RuntimeException("JWT 토큰 생성 실패: " + e.getMessage(), e);
        }
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            log.debug("JWT 토큰 검증 성공 - subject: {}", claims.getSubject());
            return true;

        } catch (ExpiredJwtException e) {
            log.warn("만료된 JWT 토큰: {}", e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 JWT 토큰: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            log.warn("잘못된 형식의 JWT 토큰: {}", e.getMessage());
            return false;
        } catch (SecurityException e) {
            log.warn("JWT 서명 검증 실패: {}", e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            log.warn("빈 JWT 토큰: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("JWT 토큰 검증 중 알 수 없는 오류", e);
            return false;
        }
    }

    public String extractEmail(String token) {
        try {
            Claims claims = getClaims(token);
            return claims.get("email", String.class);
        } catch (Exception e) {
            log.error("JWT에서 이메일 추출 실패", e);
            return null;
        }
    }

    public String extractName(String token) {
        try {
            Claims claims = getClaims(token);
            return claims.get("name", String.class);
        } catch (Exception e) {
            log.error("JWT에서 이름 추출 실패", e);
            return null;
        }
    }

    public String extractPicture(String token) {
        try {
            Claims claims = getClaims(token);
            return claims.get("picture", String.class);
        } catch (Exception e) {
            log.error("JWT에서 프로필 사진 추출 실패", e);
            return null;
        }
    }

    public String extractSubject(String token) {
        try {
            Claims claims = getClaims(token);
            return claims.getSubject();
        } catch (Exception e) {
            log.error("JWT에서 subject 추출 실패", e);
            return null;
        }
    }

    public Date extractExpiration(String token) {
        try {
            Claims claims = getClaims(token);
            return claims.getExpiration();
        } catch (Exception e) {
            log.error("JWT에서 만료 시간 추출 실패", e);
            return null;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Date expiration = extractExpiration(token);
            return expiration != null && expiration.before(new Date());
        } catch (Exception e) {
            log.error("JWT 만료 확인 실패", e);
            return true; // 오류 발생 시 만료된 것으로 처리
        }
    }

    public Map<String, Object> extractAllClaims(String token) {
        try {
            Claims claims = getClaims(token);
            Map<String, Object> claimsMap = new HashMap<>();

            claimsMap.put("email", claims.get("email"));
            claimsMap.put("name", claims.get("name"));
            claimsMap.put("picture", claims.get("picture"));
            claimsMap.put("subject", claims.getSubject());
            claimsMap.put("issuedAt", claims.getIssuedAt());
            claimsMap.put("expiration", claims.getExpiration());

            return claimsMap;
        } catch (Exception e) {
            log.error("JWT에서 모든 클레임 추출 실패", e);
            return new HashMap<>();
        }
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public void debugToken(String token) {
        try {
            log.info("=== JWT 토큰 디버그 정보 ===");
            log.info("토큰 길이: {}", token.length());

            String[] parts = token.split("\\.");
            log.info("토큰 파트 수: {}", parts.length);

            if (parts.length == 3) {
                String header = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
                log.info("헤더: {}", header);

                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                log.info("페이로드: {}", payload);
            }

            Claims claims = getClaims(token);
            log.info("클레임: {}", claims);

        } catch (Exception e) {
            log.error("JWT 토큰 디버그 실패", e);
        }
    }
}