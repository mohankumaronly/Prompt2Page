package com.rockrager.authentication.service;

import com.rockrager.authentication.entity.AuthProvider;
import com.rockrager.authentication.entity.User;
import com.rockrager.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Extract user info from Google
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String firstName = (String) attributes.get("given_name");
        String lastName = (String) attributes.get("family_name");
        String googleId = (String) attributes.get("sub");

        log.info("Google login attempt for email: {}", email);

        // Check if user exists by email
        Optional<User> existingUser = userRepository.findByEmail(email);
        User user;

        if (existingUser.isPresent()) {
            user = existingUser.get();

            // Case 1: User already has Google account linked
            if (user.getGoogleId() != null && user.getGoogleId().equals(googleId)) {
                log.info("Existing Google user logging in: {}", email);
            }
            // Case 2: User exists with LOCAL auth - Link Google account
            else if (user.getAuthProvider() == AuthProvider.LOCAL && user.getGoogleId() == null) {
                user.setGoogleId(googleId);
                // Keep authProvider as LOCAL (they can still use password)
                user = userRepository.save(user);
                log.info("Linked Google account to existing local user: {}", email);
            }
            // Case 3: Different Google account trying to use same email (should not happen)
            else if (user.getGoogleId() != null && !user.getGoogleId().equals(googleId)) {
                log.warn("Email {} already linked to different Google account", email);
                throw new RuntimeException("This email is already associated with a different Google account");
            }
        } else {
            // Case 4: New user - Create account with Google
            user = User.builder()
                    .firstName(firstName != null ? firstName : "Google")
                    .lastName(lastName != null ? lastName : "User")
                    .email(email)
                    .password("") // No password for Google users initially
                    .emailVerified(true) // Google emails are verified
                    .otpEnabled(false) // Disable OTP for Google users
                    .role("USER")
                    .googleId(googleId)
                    .authProvider(AuthProvider.GOOGLE)
                    .build();
            user = userRepository.save(user);
            log.info("Created new user with Google authentication: {}", email);
        }

        // Return OAuth2User with authorities
        return new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
                attributes,
                "email"
        );
    }
}