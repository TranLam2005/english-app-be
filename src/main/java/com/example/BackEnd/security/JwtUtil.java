package com.example.BackEnd.security;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;

@Component
public class JwtUtil {
    private final String SECRET_KEY = "thisIsASecretKeyThatIsLongEnough1234567890"; // signature to authenticated jwt token
    private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes()); // about minutes i will answer
    public Claims extracClaims(String token) {
        try {
            String[] parts = token.split("\\.");
            String headerToken = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            ObjectMapper mapper = new ObjectMapper();
            JsonNode headerJson = mapper.readTree(headerToken);
            JsonNode kidJson = headerJson.get("kid");
            if (kidJson == null) {
                if (isValidFacebookToken(token, "722531733585802", "002132a9226cb1f7ad88aa6c09c84914")) {
                    String userId = getUserId(token, "722531733585802", "002132a9226cb1f7ad88aa6c09c84914");
                    Claims claims = Jwts.claims();
                    claims.setSubject(userId);
                    claims.setIssuedAt(new Date());
                    claims.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 ));
                    return claims;
                }
                return (Claims) Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
            }
            else {
                String kid = kidJson.asText();
                if (isGoogleKid(kid)) {
                    PublicKey publicKey = getPublicKey(kid);
                    return (Claims) Jwts.parserBuilder()
                            .setSigningKey(publicKey)
                            .build()
                            .parseClaimsJws(token)
                            .getBody();
                }
                else {
                    throw new RuntimeException("Signature invalid");
                }
            }
        }
        catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }
    public String extractUserName (String token) {
        return extracClaims(token).getSubject();
    }
    public boolean isTokenExpired(String token) {
        return extracClaims(token).getExpiration().before(new Date());
    }
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
    public String generateToken(String username) {
        username = username.trim();
        return Jwts.builder()
                .setSubject((String) username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((System.currentTimeMillis() + 1000*60*60)))
                .signWith(key)
                .compact();
    }



    // verify token from google


    // follow my opinion this function will check kid be passed is validate with kid in url of google
    // use ObjectMapper to map Json keys to Object in Java
    // JsonNode has a method is .elements() will return value has type Iterator<JsonNode> to loop elements
    //
    public static PublicKey getPublicKey(String kid) throws Exception {
        String url = "https://www.googleapis.com/oauth2/v3/certs";
        ObjectMapper mapper = new ObjectMapper();
        JsonNode keys = mapper.readTree(new URL(url)).get("keys");
        Iterator<JsonNode> it = keys.elements();
        while(it.hasNext()) {
            JsonNode key = it.next();
            if(key.get("kid").asText().equals(kid)) {
                String n = key.get("n").asText();
                String e = key.get("e").asText();
                byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
                byte[] exponentBytes = Base64.getUrlDecoder().decode(e);
                BigInteger modulus = new BigInteger(1, modulusBytes);
                BigInteger exponent = new BigInteger(1, exponentBytes);
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // get instance RSA for keyFactory to generate RSAPublicKey RSA
                return keyFactory.generatePublic(publicKeySpec);
            }

        }
        throw new RuntimeException("Invalid key");
    }
    public boolean isGoogleKid (String kid) {
        return kid != null && (kid.startsWith("bba") || kid.startsWith("bb4"));
    }

    // validate token from facebook

    public boolean isValidFacebookToken (String token, String appId, String appSecret) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            String urlStr = String.format(
                    "https://graph.facebook.com/debug_token?input_token=%s&access_token=%s|%s",
                    token, appId, appSecret
            );

            String response = restTemplate.getForObject(urlStr, String.class);
            ObjectMapper mapper = new ObjectMapper();
            JsonNode responseJson  = mapper.readTree(response);
            JsonNode data = responseJson.get("data");
            return data.get("is_valid").asBoolean();
        }
        catch (Exception e) {
            throw new RuntimeException("Error verifying Facebook access token: " + e.getMessage());
        }
    }

    public String getUserId(String token, String appId, String appSecret) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            String urlStr = String.format(
                    "https://graph.facebook.com/debug_token?input_token=%s&access_token=%s|%s",
                    token, appId, appSecret
            );
            String response = restTemplate.getForObject(urlStr, String.class);
            ObjectMapper mapper = new ObjectMapper();
            JsonNode responseJson = mapper.readTree(response);
            JsonNode data = responseJson.get("data");
            return data.get("user_id").asText();
        }
        catch (Exception e) {
            throw new RuntimeException("Error verifying Facebook access token: " + e.getMessage());
        }
    }
}
