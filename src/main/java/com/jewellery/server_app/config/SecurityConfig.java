package com.jewellery.server_app.config;

import com.jewellery.server_app.jwt.JwtAuthenticationEntryPoint;
import com.jewellery.server_app.jwt.JwtAuthenticationFilter;
import com.jewellery.server_app.service.CustomOAuth2UserService;
import com.jewellery.server_app.service.CustomUserDetailsService;
import com.jewellery.server_app.jwt.HttpCookieOAuth2AuthorizationRequestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Autowired
  private CustomUserDetailsService userDetailsService;

  @Autowired
  private JwtAuthenticationEntryPoint authenticationEntryPoint;

  @Autowired
  private JwtAuthenticationFilter authenticationFilter;

  @Autowired
  private CustomOAuth2UserService customOAuth2UserService;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Bean
  public AuthenticationManager authManager(HttpSecurity http) throws Exception {
    AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(
      AuthenticationManagerBuilder.class
    );
    authenticationManagerBuilder
      .userDetailsService(userDetailsService)
      .passwordEncoder(passwordEncoder);
    return authenticationManagerBuilder.build();
  }

  @Bean
  public AuthorizationRequestRepository<OAuth2AuthorizationRequest> cookieAuthorizationRequestRepository() {
    return new HttpCookieOAuth2AuthorizationRequestRepository();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .cors(Customizer.withDefaults())
      .csrf(csrf -> csrf.disable())
      .exceptionHandling(exceptionHandling ->
        exceptionHandling.authenticationEntryPoint(authenticationEntryPoint)
      )
      .sessionManagement(sessionManagement ->
        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      )
      .authorizeHttpRequests(authorizeRequests ->
        authorizeRequests
          .requestMatchers("/api/auth/**")
          .permitAll()
          .requestMatchers("/api/admin/**")
          .hasRole("ADMIN")
          .requestMatchers("/api/user/**")
          .hasAnyRole("USER", "ADMIN")
          .anyRequest()
          .authenticated()
      )
      .oauth2Login(oauth2Login ->
        oauth2Login
          .authorizationEndpoint(authorizationEndpoint ->
            authorizationEndpoint
              .baseUri("/oauth2/authorization")
              .authorizationRequestRepository(
                cookieAuthorizationRequestRepository()
              )
          )
          .redirectionEndpoint(redirectionEndpoint ->
            redirectionEndpoint.baseUri("/login/oauth2/code/*")
          )
          .userInfoEndpoint(userInfoEndpoint ->
            userInfoEndpoint.userService(customOAuth2UserService)
          )
      );

    http.addFilterBefore(
      authenticationFilter,
      UsernamePasswordAuthenticationFilter.class
    );

    return http.build();
  }
}






// package com.jewellery.server_app.config;

// import com.jewellery.server_app.jwt.JwtAuthenticationEntryPoint;
// import com.jewellery.server_app.jwt.JwtAuthenticationFilter;
// import com.jewellery.server_app.service.CustomOAuth2UserService;
// import com.jewellery.server_app.service.CustomUserDetailsService;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.config.Customizer;
// import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.oauth2.client.registration.ClientRegistration;
// import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
// import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
// import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
// import org.springframework.security.oauth2.core.AuthorizationGrantType;
// import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
// import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

//   @Autowired
//   private CustomUserDetailsService userDetailsService;

//   @Autowired
//   private JwtAuthenticationEntryPoint authenticationEntryPoint;

//   @Autowired
//   private JwtAuthenticationFilter authenticationFilter;

//   @Autowired
//   private CustomOAuth2UserService customOAuth2UserService;

//   @Autowired
//   private PasswordEncoder passwordEncoder;

//   @Bean
//   public AuthenticationManager authManager(HttpSecurity http) throws Exception {
//     AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(
//       AuthenticationManagerBuilder.class
//     );
//     authenticationManagerBuilder
//       .userDetailsService(userDetailsService)
//       .passwordEncoder(passwordEncoder);
//     return authenticationManagerBuilder.build();
//   }

//   @Bean
//   public AuthorizationRequestRepository<OAuth2AuthorizationRequest> cookieAuthorizationRequestRepository() {
//     return new com.jewellery.server_app.jwt.HttpCookieOAuth2AuthorizationRequestRepository();
//   }

//   @Bean
//   public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//     http
//       .cors(Customizer.withDefaults())
//       .csrf(csrf -> csrf.disable())
//       .exceptionHandling(exceptionHandling ->
//         exceptionHandling.authenticationEntryPoint(authenticationEntryPoint)
//       )
//       .sessionManagement(sessionManagement ->
//         sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//       )
//       .authorizeHttpRequests(authorizeRequests ->
//         authorizeRequests
//           .requestMatchers("/api/auth/**")
//           .permitAll()
//           .requestMatchers("/api/admin/**")
//           .hasRole("ADMIN")
//           .requestMatchers("/api/user/**")
//           .hasAnyRole("USER", "ADMIN")
//           .anyRequest()
//           .authenticated()
//       )
//       .oauth2Login(oauth2Login ->
//         oauth2Login
//           .authorizationEndpoint(authorizationEndpoint ->
//             authorizationEndpoint
//               .baseUri("/oauth2/authorization")
//               .authorizationRequestRepository(
//                 cookieAuthorizationRequestRepository()
//               )
//           )
//           .redirectionEndpoint(redirectionEndpoint ->
//             redirectionEndpoint.baseUri("/oauth2/callback/*")
//           )
//           .userInfoEndpoint(userInfoEndpoint ->
//             userInfoEndpoint.userService(customOAuth2UserService)
//           )
//       );

//     http.addFilterBefore(
//       authenticationFilter,
//       UsernamePasswordAuthenticationFilter.class
//     );

//     return http.build();
//   }
// }
