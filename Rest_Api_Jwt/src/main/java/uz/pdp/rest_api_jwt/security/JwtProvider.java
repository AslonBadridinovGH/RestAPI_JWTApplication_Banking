package uz.pdp.rest_api_jwt.security;
import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtProvider {

    static long expireTime = 36_000_000;
    static String keyword = "thissecritywordTokenCLasdasd!!!";

    // GENERATION TOKEN
    public static String generateToken(String username) {

        Date expireDate = new Date(System.currentTimeMillis() + expireTime);
        String token = Jwts
                .builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(SignatureAlgorithm.HS512, keyword)
                .compact();
        return token;
    }

    // VALIDATION   TOKEN
    public boolean validateToken(String token) {
        try {
                 Jwts
                    .parser()
                    .setSigningKey(keyword)
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("Expired Jwt token");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // PARSE  TOKEN
    public String getUsernameFromToken(String token) {

        String username = Jwts
                .parser()
                .setSigningKey(keyword)
                .parseClaimsJws(token)
                .getBody().getSubject();
        return username;
    }
}
