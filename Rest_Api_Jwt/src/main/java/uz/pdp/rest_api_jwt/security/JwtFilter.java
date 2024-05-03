package uz.pdp.rest_api_jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import uz.pdp.rest_api_jwt.service.MyAuthService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// THE REQUEST ALWAYS COMES TO THIS FILTER BEFORE THE CONTROLLER:
@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    JwtProvider   jwtProvider;

    @Autowired
    MyAuthService myAuthService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Get token from HttpServletRequest:
        // Key of Headers in POSTMAN: Authorization and value
        String token = request.getHeader("Authorization");

        // if authorization exists and starts with Bearer
        if (token!=null && token.startsWith("Bearer")){

        // WE JUST SHOT THE TOKEN ITSELF
        token = token.substring(7);

        // WE HAVE VALIDATED THE TOKEN (THE TOKEN IS NOT CORRUPTED AND HAS NOT EXPIRED)
        boolean validateToken = jwtProvider.validateToken(token);
        if (validateToken){

        // GOT USERNAME FROM TOKEN
        String username = jwtProvider.getUsernameFromToken(token);

        // WE ARE SEARCHING IN LIST OR BASE, GET USER DETAILS THROUGH USERNAME
        UserDetails userDetails = myAuthService.loadUserByUsername(username);

        // WE CAN CREATE AUTHENTICATION THROUGH USER DETAILS .
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        // WE SHOW WHO ACCESSED SYSTEM ( SecurityContextHolder ).
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
       }
    }
        filterChain.doFilter(request, response);
    }
}
