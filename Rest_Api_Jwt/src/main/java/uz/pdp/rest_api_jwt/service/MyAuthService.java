package uz.pdp.rest_api_jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import uz.pdp.rest_api_jwt.repository.CardRepository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class MyAuthService implements UserDetailsService {

     @Autowired
     PasswordEncoder  passwordEncoder;
     @Autowired
     CardRepository cardRepository;

    // Check Username on base
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
        {
         List<User> userList = new ArrayList<>(
             Arrays.asList(
                            new User("Ali", passwordEncoder.encode("ali123"),new ArrayList<>()),
                            new User("Vali",passwordEncoder.encode("vali123"),new ArrayList<>()),
                            new User("Abror", passwordEncoder.encode("abror123"),new ArrayList<>()),
                            new User("Alisher", passwordEncoder.encode("alisher123"),new ArrayList<>())
                          )
         );

            for (User user : userList) {
               if (user.getUsername().equals(username))
                   return user;
            }

            throw new UsernameNotFoundException("User was not found");
        }
}
