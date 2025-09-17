package com.security.test1.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.test1.dto.OAuthAttributes;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class OAuthService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String kakaoClientId;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String kakaoClientSecret;

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;

    @Value("${spring.security.oauth2.client.registration.naver.client-secret}")
    private String naverClientSecret;

    public OAuthService() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Google OAuth 처리 알고리즘
     */
    public OAuthAttributes processGoogleCallback(String code) {
        try {
            log.info("Google OAuth 처리 시작 - code: {}", code);

            // 1단계: Authorization Code로 Access Token 획득
            String accessToken = getGoogleAccessToken(code);
            log.info("Google Access Token 획득 성공");

            // 2단계: Access Token으로 사용자 정보 조회
            Map<String, Object> userInfo = getGoogleUserInfo(accessToken);
            log.info("Google 사용자 정보 조회 성공: {}", userInfo);

            // 3단계: OAuthAttributes 객체 생성
            return createGoogleOAuthAttributes(userInfo);

        } catch (Exception e) {
            log.error("Google OAuth 처리 중 오류 발생", e);
            throw new RuntimeException("Google OAuth 처리 실패: " + e.getMessage(), e);
        }
    }

    /**
     * Kakao OAuth 처리 알고리즘
     */
    public OAuthAttributes processKakaoCallback(String code) {
        try {
            log.info("Kakao OAuth 처리 시작 - code: {}", code);

            // 1단계: Authorization Code로 Access Token 획득
            String accessToken = getKakaoAccessToken(code);
            log.info("Kakao Access Token 획득 성공");

            // 2단계: Access Token으로 사용자 정보 조회
            Map<String, Object> userInfo = getKakaoUserInfo(accessToken);
            log.info("Kakao 사용자 정보 조회 성공: {}", userInfo);

            // 3단계: OAuthAttributes 객체 생성
            return createKakaoOAuthAttributes(userInfo);

        } catch (Exception e) {
            log.error("Kakao OAuth 처리 중 오류 발생", e);
            throw new RuntimeException("Kakao OAuth 처리 실패: " + e.getMessage(), e);
        }
    }

    /**
     * Naver OAuth 처리 알고리즘
     */
    public OAuthAttributes processNaverCallback(String code, String state) {
        try {
            log.info("Naver OAuth 처리 시작 - code: {}, state: {}", code, state);

            // 1단계: Authorization Code로 Access Token 획득
            String accessToken = getNaverAccessToken(code, state);
            log.info("Naver Access Token 획득 성공");

            // 2단계: Access Token으로 사용자 정보 조회
            Map<String, Object> userInfo = getNaverUserInfo(accessToken);
            log.info("Naver 사용자 정보 조회 성공: {}", userInfo);

            // 3단계: OAuthAttributes 객체 생성
            return createNaverOAuthAttributes(userInfo);

        } catch (Exception e) {
            log.error("Naver OAuth 처리 중 오류 발생", e);
            throw new RuntimeException("Naver OAuth 처리 실패: " + e.getMessage(), e);
        }
    }

    // ==================== Google 관련 메서드 ====================

    private String getGoogleAccessToken(String code) throws Exception {
        String tokenUrl = "https://oauth2.googleapis.com/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", googleClientId);
        params.add("client_secret", googleClientSecret);
        params.add("code", code);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", "http://localhost:8080/api/auth/google/callback");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(tokenUrl, request, String.class);

        if (response.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Google 토큰 요청 실패: " + response.getStatusCode());
        }

        JsonNode jsonNode = objectMapper.readTree(response.getBody());
        return jsonNode.get("access_token").asText();
    }

    private Map<String, Object> getGoogleUserInfo(String accessToken) throws Exception {
        String userInfoUrl = "https://www.googleapis.com/oauth2/v2/userinfo";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<?> request = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(userInfoUrl, HttpMethod.GET, request, String.class);

        if (response.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Google 사용자 정보 조회 실패: " + response.getStatusCode());
        }

        return objectMapper.readValue(response.getBody(), Map.class);
    }

    private OAuthAttributes createGoogleOAuthAttributes(Map<String, Object> userInfo) {
        return new OAuthAttributes(
                userInfo,
                "sub",
                (String) userInfo.get("name"),
                (String) userInfo.get("email"),
                (String) userInfo.get("picture")
        );
    }

    // ==================== Kakao 관련 메서드 ====================

    private String getKakaoAccessToken(String code) throws Exception {
        String tokenUrl = "https://kauth.kakao.com/oauth/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", kakaoClientId);
        params.add("client_secret", kakaoClientSecret);
        params.add("code", code);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", "http://localhost:8080/api/auth/kakao/callback"); // 수정된 리디렉션 URI

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        log.info("카카오 토큰 요청 파라미터: {}", params);
        ResponseEntity<String> response = restTemplate.postForEntity(tokenUrl, request, String.class);

        if (response.getStatusCode() != HttpStatus.OK) {
            log.error("카카오 토큰 요청 실패 - Status: {}, Body: {}", response.getStatusCode(), response.getBody());
            throw new RuntimeException("Kakao 토큰 요청 실패: " + response.getStatusCode());
        }

        JsonNode jsonNode = objectMapper.readTree(response.getBody());
        String accessToken = jsonNode.get("access_token").asText();
        log.info("카카오 액세스 토큰 획득 성공");
        return accessToken;
    }

    private Map<String, Object> getKakaoUserInfo(String accessToken) throws Exception {
        String userInfoUrl = "https://kapi.kakao.com/v2/user/me";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<?> request = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(userInfoUrl, HttpMethod.GET, request, String.class);

        if (response.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Kakao 사용자 정보 조회 실패: " + response.getStatusCode());
        }

        return objectMapper.readValue(response.getBody(), Map.class);
    }

    @SuppressWarnings("unchecked")
    private OAuthAttributes createKakaoOAuthAttributes(Map<String, Object> userInfo) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) userInfo.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        return new OAuthAttributes(
                userInfo,
                "id",
                (String) profile.get("nickname"),
                (String) kakaoAccount.get("email"),
                (String) profile.get("profile_image_url")
        );
    }

    // ==================== Naver 관련 메서드 ====================

    private String getNaverAccessToken(String code, String state) throws Exception {
        String tokenUrl = "https://nid.naver.com/oauth2.0/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", naverClientId);
        params.add("client_secret", naverClientSecret);
        params.add("code", code);
        params.add("state", state);
        params.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(tokenUrl, request, String.class);

        if (response.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Naver 토큰 요청 실패: " + response.getStatusCode());
        }

        JsonNode jsonNode = objectMapper.readTree(response.getBody());
        return jsonNode.get("access_token").asText();
    }

    private Map<String, Object> getNaverUserInfo(String accessToken) throws Exception {
        String userInfoUrl = "https://openapi.naver.com/v1/nid/me";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<?> request = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(userInfoUrl, HttpMethod.GET, request, String.class);

        if (response.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Naver 사용자 정보 조회 실패: " + response.getStatusCode());
        }

        return objectMapper.readValue(response.getBody(), Map.class);
    }

    @SuppressWarnings("unchecked")
    private OAuthAttributes createNaverOAuthAttributes(Map<String, Object> userInfo) {
        Map<String, Object> response = (Map<String, Object>) userInfo.get("response");

        return new OAuthAttributes(
                userInfo,
                "id",
                (String) response.get("name"),
                (String) response.get("email"),
                (String) response.get("profile_image")
        );
    }
}