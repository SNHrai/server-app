package com.jewellery.server_app.controller;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.jewellery.server_app.jwt.JwtUtils;
import com.jewellery.server_app.model.ERole;
import com.jewellery.server_app.model.GoogleAuthRequest;
import com.jewellery.server_app.model.JwtResponse;
import com.jewellery.server_app.model.LoginRequest;
import com.jewellery.server_app.model.MessageResponse;
import com.jewellery.server_app.model.Role;
import com.jewellery.server_app.model.SignupRequest;
import com.jewellery.server_app.model.User;
import com.jewellery.server_app.repository.RoleRepository;
import com.jewellery.server_app.repository.UserRepository;
import com.jewellery.server_app.service.AuthService;
import com.jewellery.server_app.service.UserDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  @Autowired
  private AuthService authService;

  @Autowired
  private JwtUtils jwtUtils;

  @Autowired
  private RoleRepository roleRepository;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  private OAuth2AuthorizedClientService authorizedClientService;

  @Autowired
  private OAuth2AuthorizedClientRepository authorizedClientRepository;

  @Autowired
  private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

  @PostMapping("/login")
  public ResponseEntity<JwtResponse> authenticateUser(
    @Valid @RequestBody LoginRequest loginRequest
  ) {
    Authentication authentication = authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(
        loginRequest.getEmail(),
        loginRequest.getPassword()
      )
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    User user = userDetails.getUser();

    // List<String> roles = userDetails.getAuthorities().stream()
    //         .map(GrantedAuthority::getAuthority)
    //         .collect(Collectors.toList());
    List<String> userRoles = userDetails
      .getAuthorities()
      .stream()
      .map(item -> item.getAuthority().replaceFirst("ROLE_", ""))
      .collect(Collectors.toList());

    JwtResponse jwtResponse = new JwtResponse(
      jwt,
      user.getEmail(),
      user.getFirstName(),
      user.getLastName(),
      user.getProfession(),
      user.getCountry(),
      userRoles // Pass roles as a List<String>
    );

    return ResponseEntity.ok(jwtResponse);
  }

  @PostMapping("/register")
  public ResponseEntity<?> registerUser(
    @Valid @RequestBody SignupRequest signupRequest
  ) {
    if (authService.existsByEmail(signupRequest.getEmail())) {
      return ResponseEntity
        .badRequest()
        .body(new MessageResponse("Email is already in use!"));
    }

    User user = new User();
    user.setFirstName(signupRequest.getFirstName());
    user.setLastName(signupRequest.getLastName());
    user.setEmail(signupRequest.getEmail());
    user.setPassword(signupRequest.getPassword());
    user.setProfession(signupRequest.getProfession());
    user.setCountry(signupRequest.getCountry());

    Set<String> strRoles = signupRequest.getRoles();
    Set<Role> roles = new HashSet<>();
    if (strRoles == null) {
      Role userRole = roleRepository
        .findByName(ERole.ROLE_USER.name())
        .orElseThrow(() -> new RuntimeException("Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
          case "admin":
            Role adminRole = roleRepository
              .findByName(ERole.ROLE_ADMIN.name())
              .orElseThrow(() ->
                new RuntimeException("Role is not found.")
              );
            roles.add(adminRole);
            break;
          default:
            Role userRole = roleRepository
              .findByName(ERole.ROLE_USER.name())
              .orElseThrow(() ->
                new RuntimeException("Role is not found.")
              );
            roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    authService.saveUser(user);

    // Authenticate the user and generate a token
    Authentication authentication = authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(
        signupRequest.getEmail(),
        signupRequest.getPassword()
      )
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    List<String> userRoles = userDetails
      .getAuthorities()
      .stream()
      .map(item -> item.getAuthority().replaceFirst("ROLE_", ""))
      .collect(Collectors.toList());

    JwtResponse jwtResponse = new JwtResponse(
      jwt,
      user.getEmail(),
      user.getFirstName(),
      user.getLastName(),
      user.getProfession(),
      user.getCountry(),
      userRoles
    );

    return ResponseEntity.ok(jwtResponse);
  }

  @PostMapping("/google-login")
  public ResponseEntity<?> googleLogin(
    @RequestBody GoogleAuthRequest googleAuthRequest,
    Authentication authentication,
    HttpServletRequest request
  ) {
    try {
      Payload payload = verifyGoogleIdToken(googleAuthRequest.getIdToken());
      String email = payload.getEmail();

      User user = authService
        .getUserByEmail(email)
        .orElseGet(() -> {
          User newUser = new User();
          newUser.setEmail(email);
          newUser.setFirstName((String) payload.get("given_name"));
          newUser.setLastName((String) payload.get("family_name"));
          newUser.setRoles(
            Collections.singleton(
              roleRepository
                .findByName(ERole.ROLE_USER.name())
                .orElseThrow(() ->
                  new RuntimeException("Role is not found.")
                )
            )
          );
          return authService.saveUser(newUser);
        });

      UserDetailsImpl userDetails = UserDetailsImpl.build(user);

      Authentication auth = new UsernamePasswordAuthenticationToken(
        userDetails,
        null,
        userDetails.getAuthorities()
      );

      SecurityContextHolder.getContext().setAuthentication(auth);
      String jwt = jwtUtils.generateJwtToken(auth);

      // List<String> roles = userDetails.getAuthorities().stream()
      //         .map(GrantedAuthority::getAuthority)
      //         .collect(Collectors.toList());
      List<String> userRoles = userDetails
        .getAuthorities()
        .stream()
        .map(item -> item.getAuthority().replaceFirst("ROLE_", ""))
        .collect(Collectors.toList());

      JwtResponse jwtResponse = new JwtResponse(
        jwt,
        user.getEmail(),
        user.getFirstName(),
        user.getLastName(),
        user.getProfession(),
        user.getCountry(),
        userRoles // Pass roles as a List<String>
      );

      return ResponseEntity.ok(jwtResponse);
    } catch (GeneralSecurityException | IOException e) {
      return ResponseEntity
        .badRequest()
        .body(new MessageResponse("Invalid Google ID token."));
    }
  }

  private Payload verifyGoogleIdToken(String idTokenString)
    throws GeneralSecurityException, IOException {
    GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
      new NetHttpTransport(),
      new JacksonFactory()
    )
      .setAudience(Collections.singletonList("YOUR_GOOGLE_CLIENT_ID"))
      .build();

    GoogleIdToken idToken = verifier.verify(idTokenString);
    if (idToken != null) {
      return idToken.getPayload();
    } else {
      throw new GeneralSecurityException("Invalid ID token.");
    }
  }
}
// package com.jewellery.server_app.controller;
// import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
// import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
// import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
// import com.google.api.client.http.javanet.NetHttpTransport;
// import com.google.api.client.json.jackson2.JacksonFactory;
// import com.jewellery.server_app.jwt.JwtUtils;
// import com.jewellery.server_app.model.ERole;
// import com.jewellery.server_app.model.GoogleAuthRequest;
// import com.jewellery.server_app.model.JwtResponse;
// import com.jewellery.server_app.model.LoginRequest;
// import com.jewellery.server_app.model.MessageResponse;
// import com.jewellery.server_app.model.Role;
// import com.jewellery.server_app.model.SignupRequest;
// import com.jewellery.server_app.model.User;
// import com.jewellery.server_app.repository.RoleRepository;
// import com.jewellery.server_app.repository.UserRepository;
// import com.jewellery.server_app.service.AuthService;
// import com.jewellery.server_app.service.UserDetailsImpl;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.validation.Valid;
// import java.io.IOException;
// import java.security.GeneralSecurityException;
// import java.util.Collections;
// import java.util.HashSet;
// import java.util.List;
// import java.util.Set;
// import java.util.stream.Collectors;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
// import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
// import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
// import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
// import org.springframework.security.oauth2.core.user.OAuth2User;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RestController;
// @RestController
// @RequestMapping("/api/auth")
// public class AuthController {
//   @Autowired
//   private AuthService authService;
//   @Autowired
//   private JwtUtils jwtUtils;
//   @Autowired
//   private RoleRepository roleRepository;
//   @Autowired
//   private UserRepository userRepository;
//   @Autowired
//   private AuthenticationManager authenticationManager;
//   @Autowired
//   private OAuth2AuthorizedClientService authorizedClientService;
//   @Autowired
//   private OAuth2AuthorizedClientRepository authorizedClientRepository;
//   @Autowired
//   private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;
//   @PostMapping("/login")
//   public ResponseEntity<JwtResponse> authenticateUser(
//     @Valid @RequestBody LoginRequest loginRequest
//   ) {
//     Authentication authentication = authenticationManager.authenticate(
//       new UsernamePasswordAuthenticationToken(
//         loginRequest.getEmail(),
//         loginRequest.getPassword()
//       )
//     );
//     SecurityContextHolder.getContext().setAuthentication(authentication);
//     String jwt = jwtUtils.generateJwtToken(authentication);
//     UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//     User user = userDetails.getUser();
//     List<String> roles = userDetails
//       .getAuthorities()
//       .stream()
//       .map(item -> item.getAuthority())
//       .collect(Collectors.toList());
//     JwtResponse jwtResponse = new JwtResponse(
//       jwt,
//       user.getEmail(),
//       user.getFirstName(),
//       user.getLastName(),
//       user.getProfession(),
//       user.getCountry(),
//       roles // Pass roles as a List<String>
//     );
//     return ResponseEntity.ok(jwtResponse);
//   }
//   // @PostMapping("/register")
//   // public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
//   //     if (authService.existsByEmail(signupRequest.getEmail())) {
//   //         return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
//   //     }
//   //     User user = new User();
//   //     user.setFirstName(signupRequest.getFirstName());
//   //     user.setLastName(signupRequest.getLastName());
//   //     user.setEmail(signupRequest.getEmail());
//   //     user.setPassword(signupRequest.getPassword());
//   //     user.setProfession(signupRequest.getProfession());
//   //     user.setCountry(signupRequest.getCountry());
//   //     Set<String> strRoles = signupRequest.getRoles();
//   //     Set<Role> roles = new HashSet<>();
//   //     if (strRoles == null) {
//   //         Role userRole = roleRepository.findByName(ERole.ROLE_USER.name())
//   //                 .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//   //         roles.add(userRole);
//   //     } else {
//   //         strRoles.forEach(role -> {
//   //             switch (role) {
//   //                 case "admin":
//   //                     Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN.name())
//   //                             .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//   //                     roles.add(adminRole);
//   //                     break;
//   //                 default:
//   //                     Role userRole = roleRepository.findByName(ERole.ROLE_USER.name())
//   //                             .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//   //                     roles.add(userRole);
//   //             }
//   //         });
//   //     }
//   //     user.setRoles(roles);
//   //     authService.saveUser(user);
//   //     return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
//   // }
//   @PostMapping("/register")
//   public ResponseEntity<?> registerUser(
//     @Valid @RequestBody SignupRequest signupRequest
//   ) {
//     if (authService.existsByEmail(signupRequest.getEmail())) {
//       return ResponseEntity
//         .badRequest()
//         .body(new MessageResponse("Email is already in use!"));
//     }
//     User user = new User();
//     user.setFirstName(signupRequest.getFirstName());
//     user.setLastName(signupRequest.getLastName());
//     user.setEmail(signupRequest.getEmail());
//     user.setPassword(signupRequest.getPassword());
//     user.setProfession(signupRequest.getProfession());
//     user.setCountry(signupRequest.getCountry());
//     Set<String> strRoles = signupRequest.getRoles();
//     Set<Role> roles = new HashSet<>();
//     if (strRoles == null) {
//       Role userRole = roleRepository
//         .findByName(ERole.ROLE_USER.name())
//         .orElseThrow(() -> new RuntimeException("Role is not found."));
//       roles.add(userRole);
//     } else {
//       strRoles.forEach(role -> {
//         switch (role) {
//           case "admin":
//             Role adminRole = roleRepository
//               .findByName(ERole.ROLE_ADMIN.name())
//               .orElseThrow(() ->
//                 new RuntimeException("Role is not found.")
//               );
//             roles.add(adminRole);
//             break;
//           default:
//             Role userRole = roleRepository
//               .findByName(ERole.ROLE_USER.name())
//               .orElseThrow(() ->
//                 new RuntimeException("Role is not found.")
//               );
//             roles.add(userRole);
//         }
//       });
//     }
//     user.setRoles(roles);
//     authService.saveUser(user);
//     // Authenticate the user and generate a token
//     Authentication authentication = authenticationManager.authenticate(
//       new UsernamePasswordAuthenticationToken(
//         signupRequest.getEmail(),
//         signupRequest.getPassword()
//       )
//     );
//     SecurityContextHolder.getContext().setAuthentication(authentication);
//     String jwt = jwtUtils.generateJwtToken(authentication);
//     UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//     List<String> userRoles = userDetails
//       .getAuthorities()
//       .stream()
//       .map(item -> item.getAuthority())
//       .collect(Collectors.toList());
//     JwtResponse jwtResponse = new JwtResponse(
//       jwt,
//       user.getEmail(),
//       user.getFirstName(),
//       user.getLastName(),
//       user.getProfession(),
//       user.getCountry(),
//       userRoles
//     );
//     return ResponseEntity.ok(jwtResponse);
//   }
//   @PostMapping("/google-login")
//   public ResponseEntity<?> googleLogin(
//     @RequestBody GoogleAuthRequest googleAuthRequest,
//     Authentication authentication,
//     HttpServletRequest request
//   ) {
//     try {
//       Payload payload = verifyGoogleIdToken(googleAuthRequest.getIdToken());
//       String email = payload.getEmail();
//       User user = authService
//         .getUserByEmail(email)
//         .orElseGet(() -> {
//           User newUser = new User();
//           newUser.setEmail(email);
//           newUser.setFirstName((String) payload.get("given_name"));
//           newUser.setLastName((String) payload.get("family_name"));
//           newUser.setRoles(
//             Collections.singleton(
//               roleRepository
//                 .findByName(ERole.ROLE_USER.name())
//                 .orElseThrow(() ->
//                   new RuntimeException("Role is not found.")
//                 )
//             )
//           );
//           return authService.saveUser(newUser);
//         });
//       UserDetailsImpl userDetails = UserDetailsImpl.build(user);
//       Authentication auth = new UsernamePasswordAuthenticationToken(
//         userDetails,
//         null,
//         userDetails.getAuthorities()
//       );
//       SecurityContextHolder.getContext().setAuthentication(auth);
//       String jwt = jwtUtils.generateJwtToken(auth);
//       List<String> roles = userDetails
//         .getAuthorities()
//         .stream()
//         .map(GrantedAuthority::getAuthority)
//         .collect(Collectors.toList());
//       JwtResponse jwtResponse = new JwtResponse(
//         jwt,
//         user.getEmail(),
//         user.getFirstName(),
//         user.getLastName(),
//         user.getProfession(),
//         user.getCountry(),
//         roles // Pass roles as a List<String>
//       );
//       return ResponseEntity.ok(jwtResponse);
//     } catch (GeneralSecurityException | IOException e) {
//       return ResponseEntity
//         .badRequest()
//         .body(new MessageResponse("Google authentication failed"));
//     }
//   }
//   private Payload verifyGoogleIdToken(String idTokenString)
//     throws GeneralSecurityException, IOException {
//     GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
//       new NetHttpTransport(),
//       new JacksonFactory()
//     )
//       .setAudience(
//         Collections.singletonList(
//           "104704098738-n405gi0ij1mmhh8klifnt664o1hr12hf.apps.googleusercontent.com"
//         )
//       )
//       .build();
//     GoogleIdToken idToken = verifier.verify(idTokenString);
//     if (idToken != null) {
//       return idToken.getPayload();
//     } else {
//       throw new IllegalStateException("Invalid ID token");
//     }
//   }
// }
// // @RestController
// // @RequestMapping("/api/auth")
// // public class AuthController {
// //     @Autowired
// //     private AuthService authService;
// //     @Autowired
// //     private JwtUtils jwtUtils;
// //     @Autowired
// //     private RoleRepository roleRepository;
// //     @Autowired
// //     private UserRepository userRepository;
// //     @Autowired
// //     private AuthenticationManager authenticationManager;
// //     @Autowired
// //     private OAuth2AuthorizedClientService authorizedClientService;
// //     @Autowired
// //     private OAuth2AuthorizedClientRepository authorizedClientRepository;
// //     @Autowired
// //     private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;
// //     @PostMapping("/login")
// //     public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
// //         Authentication authentication = authenticationManager.authenticate(
// //                 new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
// //         SecurityContextHolder.getContext().setAuthentication(authentication);
// //         String jwt = jwtUtils.generateJwtToken(authentication);
// //         UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
// //         User user = userDetails.getUser();
// //         List<String> roles = userDetails.getAuthorities().stream()
// //                 .map(item -> item.getAuthority())
// //                 .collect(Collectors.toList());
// //         return ResponseEntity.ok().body(new JwtResponse(jwt, user.getEmail(), user.getFirstName(), user.getLastName(), user.getProfession(), user.getCountry(), user.getRoles()));
// //     }
// //     @PostMapping("/register")
// // public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
// //     if (authService.existsByEmail(signupRequest.getEmail())) {
// //         return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
// //     }
// //     User user = new User();
// //     user.setFirstName(signupRequest.getFirstName());
// //     user.setLastName(signupRequest.getLastName());
// //     user.setEmail(signupRequest.getEmail());
// //     user.setPassword(signupRequest.getPassword());
// //     user.setProfession(signupRequest.getProfession());
// //     user.setCountry(signupRequest.getCountry());
// //     Set<String> strRoles = signupRequest.getRoles();
// //     Set<Role> roles = new HashSet<>();
// //     if (strRoles == null) {
// //         Role userRole = roleRepository.findByName(ERole.ROLE_USER.name())
// //                 .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
// //         roles.add(userRole);
// //     } else {
// //         strRoles.forEach(role -> {
// //             switch (role) {
// //                 case "admin":
// //                     Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN.name())
// //                             .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
// //                     roles.add(adminRole);
// //                     break;
// //                 default:
// //                     Role userRole = roleRepository.findByName(ERole.ROLE_USER.name())
// //                             .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
// //                     roles.add(userRole);
// //             }
// //         });
// //     }
// //     user.setRoles(roles);
// //     authService.saveUser(user);
// //     return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
// // }
// //     @PostMapping("/google-login")
// //     public ResponseEntity<?> googleLogin(@RequestBody GoogleAuthRequest googleAuthRequest, Authentication authentication, HttpServletRequest request) {
// //         try {
// //             Payload payload = verifyGoogleIdToken(googleAuthRequest.getIdToken());
// //             String email = payload.getEmail();
// //             User user = authService.getUserByEmail(email).orElseGet(() -> {
// //                 User newUser = new User();
// //                 newUser.setEmail(email);
// //                 newUser.setFirstName((String) payload.get("given_name"));
// //                 newUser.setLastName((String) payload.get("family_name"));
// //                 newUser.setRoles(Collections.singleton( roleRepository.findByName(ERole.ROLE_ADMIN.name())
// //                         .orElseThrow(() -> new RuntimeException("Error: Role is not found."))));
// //                 return authService.saveUser(newUser);
// //             });
// //             UserDetailsImpl userDetails = UserDetailsImpl.build(user);
// //             Authentication auth = new UsernamePasswordAuthenticationToken(
// //                     userDetails, null, userDetails.getAuthorities());
// //             SecurityContextHolder.getContext().setAuthentication(auth);
// //             String jwt = jwtUtils.generateJwtToken(auth);
// //             List<String> roles = userDetails.getAuthorities().stream()
// //                     .map(GrantedAuthority::getAuthority)
// //                     .collect(Collectors.toList());
// //             return ResponseEntity.ok(new JwtResponse(jwt, user.getEmail(), user.getFirstName(), user.getLastName(), user.getProfession(), user.getCountry(), user.getRoles()));
// //         } catch (GeneralSecurityException | IOException e) {
// //             return ResponseEntity.badRequest().body(new MessageResponse("Error: Google authentication failed"));
// //         }
// //     }
// //     private Payload verifyGoogleIdToken(String idTokenString) throws GeneralSecurityException, IOException {
// //         GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new JacksonFactory())
// //                 .setAudience(Collections.singletonList("104704098738-n405gi0ij1mmhh8klifnt664o1hr12hf.apps.googleusercontent.com"))
// //                 .build();
// //         GoogleIdToken idToken = verifier.verify(idTokenString);
// //         if (idToken != null) {
// //             return idToken.getPayload();
// //         } else {
// //             throw new IllegalStateException("Invalid ID token");
// //         }
// //     }
// // }
