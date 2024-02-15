package com.colak.springsecurityoauth2standaloneauthserverauthorizationcode;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AuthorizationCodeTest {

    @LocalServerPort
    private int port;
    @Autowired
    private WebTestClient webTestClient;

    private static final String CLIENT_ID = "oidc-client";
    private static final String CLIENT_SECRET = "{noop}secret";
    private static final String SCOPE = "openid";
    private static final String STATE = "123xyz";
    private static final String USERNAME = "user";
    private static final String PASSWORD = "password";
    private static final String REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/oidc-client";

    @Test
    void authorizationCodeGrantTypeTest() {
        // build URL
        String authorizeUrl = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port + "/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", SCOPE)
                .queryParam("state", STATE)
                .build()
                .toUriString();

        // Step 1: GET /oauth2/authorize
        String preLoginSetCookieHeader = webTestClient
                .get()
                .uri(authorizeUrl)
                .exchange()
                .expectStatus().is3xxRedirection()
                .expectHeader().exists(HttpHeaders.SET_COOKIE)
                .returnResult(String.class)
                .getResponseHeaders()
                .getFirst(HttpHeaders.SET_COOKIE);

        // Step 2: GET /login
        webTestClient.get()
                .uri("/login")
                .header(HttpHeaders.COOKIE, preLoginSetCookieHeader) // optional
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult();

        System.out.println(preLoginSetCookieHeader);

        // Step 3: POST /login
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", USERNAME);
        formData.add("password", PASSWORD);

        HttpHeaders loginResponseHeaders = webTestClient.post()
                .uri("/login")
                .header(HttpHeaders.COOKIE, preLoginSetCookieHeader)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(formData)
                .exchange()
                .expectStatus().is3xxRedirection()
                .returnResult(String.class)
                .getResponseHeaders();

        String postLoginRedirectLocation = loginResponseHeaders.getFirst(HttpHeaders.LOCATION);
        String postLoginSetCookieHeader = loginResponseHeaders.getFirst(HttpHeaders.SET_COOKIE);

        assert postLoginRedirectLocation != null;
        System.out.println(loginResponseHeaders);
        // Step 4: GET /oauth2/authorize
        String redirectUrlWithAuthorizationCode = webTestClient.get()
                .uri(postLoginRedirectLocation)
                .header(HttpHeaders.COOKIE, postLoginSetCookieHeader)
                .exchange()
                .expectStatus().is3xxRedirection()
                .returnResult(String.class)
                .getResponseHeaders()
                .getFirst(HttpHeaders.LOCATION);

        String authorizationCode = extractAuthorizationCode(redirectUrlWithAuthorizationCode);

        // Step 5: POST /oauth2/token
        webTestClient.post()
                .uri("oauth2/token")
                .headers(headers -> headers.setBasicAuth(CLIENT_ID, CLIENT_SECRET, StandardCharsets.UTF_8))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("grant_type=authorization_code&code=" + authorizationCode + "&redirect_uri="
                           + REDIRECT_URI + "&client_id" + CLIENT_ID)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("access_token").isNotEmpty();
    }

    private String extractAuthorizationCode(String redirectUri) {
        Pattern pattern = Pattern.compile("code=([^&]+)");
        Matcher matcher = pattern.matcher(redirectUri);

        if (matcher.find()) {
            return matcher.group(1);
        } else {
            throw new IllegalStateException("Authorization code not found in redirect URI");
        }
    }
}
