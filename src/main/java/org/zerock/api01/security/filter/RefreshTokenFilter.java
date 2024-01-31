package org.zerock.api01.security.filter;

import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.exception.RefreshTokenException;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final String refreshPath;

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if(!path.equals(refreshPath)) {
            log.info("skip refresh token filter......");
            filterChain.doFilter(request, response);
            return;
        }
        log.info("Refresh Token Filter...run..............1");

        Map<String, String> tokens = parseRequestJSON(request);

        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken: " + accessToken);
        log.info("refreshToken: " + refreshToken);

        try {
            checkAccessToken(accessToken);
        }catch (RefreshTokenException refreshTokenException){
            refreshTokenException.sendResponseError(response);
        }

        Map<String, Object> refreshClaims = null;

        try {
            refreshClaims = checkRefreshToken(refreshToken);
            log.info(refreshClaims);

            Integer exp = (Integer) refreshClaims.get("exp");

            Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);

            Date currnet = new Date(System.currentTimeMillis());

            long gapTime = (expTime.getTime() - currnet.getTime());

            log.info("-------------------------------------");
            log.info("current: " + currnet);
            log.info("expTime: " + expTime);
            log.info("gap: " + gapTime);

            String mid = (String) refreshClaims.get("mid");

            String accessTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 1);
            String refreshTokenvalue = tokens.get("refreshToken");

            if(gapTime < (1000 * 60 * 60 * 24 * 3)) {
                log.info("new Refresh Token required...");
                refreshTokenvalue = jwtUtil.generateToken(Map.of("mid", mid), 30);
            }

            log.info("Refresh Token result...................");
            log.info("accessToken: " + accessTokenValue);
            log.info("refreshToken: " + refreshTokenvalue);

            sendTokens(accessTokenValue, refreshTokenvalue, response);
        }catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return;
        }
    }

    private Map<String, String> parseRequestJSON(HttpServletRequest request) {
        try(Reader reader = new InputStreamReader(request.getInputStream())){
            Gson gson = new Gson();

            return gson.fromJson(reader, Map.class);
        }catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    private void checkAccessToken(String accessToken) throws RefreshTokenException {
        try {
            jwtUtil.validateToken(accessToken);
        }catch (ExpiredJwtException expiredJwtException){
            log.info("Access Token has expired");
        }catch (Exception exception){
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }

    private Map<String, Object> checkRefreshToken(String refreshToken) throws RefreshTokenException{
        try {
            Map<String, Object> values = jwtUtil.validateToken(refreshToken);
            return values;
        }catch (ExpiredJwtException expiredJwtException) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        }catch (MalformedJwtException malformedJwtException){
            log.error("MalformedJwtException-----------------------------------");
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }catch (Exception exception){
            new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
        return null;
    }

    private void sendTokens(String accessTokenValue, String refreshTokenValue, HttpServletResponse response) {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();

        String jsonStr = gson.toJson(Map.of("accessToken", accessTokenValue, "refreshToken", refreshTokenValue));

        try {
            response.getWriter().println(jsonStr);
        }catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
