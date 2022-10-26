

# Spring Authorization Server

Spring Authorization Server 是由Spring提供的提供基于OAuth2.1协议的授权服务项目。同类型的有 [keycloak](https://github.com/keycloak/keycloak)  \ [MaxKey](https://github.com/dromara/MaxKey) \ [uua](https://github.com/cloudfoundry/uaa)



## 链接

- [Spring Authorization Server 参考文档](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html)
- [example-spring-authorization-server 项目最佳实践](https://github.com/ToQuery/example-spring-authorization-server)
- OAuth2认证流程



## 前置条件

- 版本

本文以 Spring Authorization Server  `0.3.1` 为例，Spring Boot 为 `2.7.4` ，JDK为 `17` 。



- OAuth2.0 、OAuth2.0 和 OpenID Connect 1.0 协议异同





## 依赖（最小化）

```xml
<!-- 必须保留，使用SSO登录时加载登录页面会用到 -->
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-oauth2-authorization-server</artifactId>
  <version>0.3.1</version>
</dependency>
```



## 配置使用

项目需要使用非对称加密生成公私钥证书，证书用于jwk（jwt）的生成，客户端接入时也可使用授权服务暴露的证书信息生成独立的 Jwt Token 信息。引入方式可以如[官网文档](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html)所诉，动态生成公私钥如下。但该方式存在问题，例如**每次重启证书都变动**、**无法集群部署**等等。

```java
// 生成秘钥信息
private static KeyPair generateRsaKey() { 
		KeyPair keyPair;
		try {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
				throw new IllegalStateException(ex);
		}
		return keyPair;
}

// 获取公私钥
public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
}

```



因此根据项目情况使用使用固定公私钥证书，保证唯一不变。并放入项目 resources/jwts 目录，如下



```java
/**
 * @author ToQuery
 */
@Data
@ConfigurationProperties(prefix = "app.oauth")
public class OAuthAuthorizationProperties {
    private String keyId = "123456";
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
  	{
        try {
            publicKey = RsaKeyConverters.x509().convert(new DefaultResourceLoader().getResource(ResourceLoader.CLASSPATH_URL_PREFIX + "jwts" + File.separator + "public.pub").getInputStream());
        } catch (IOException e) {
            log.error("加载JWT公钥失败", e);
            throw new RuntimeException(e);
        }
        try {
            privateKey = RsaKeyConverters.pkcs8().convert(new DefaultResourceLoader().getResource(ResourceLoader.CLASSPATH_URL_PREFIX + "jwts" + File.separator + "private.key").getInputStream());
        } catch (IOException e) {
            log.error("加载JWT私钥失败", e);
            throw new RuntimeException(e);
        }
    }
}
```

证书准备完毕后需要配置jwt解码bean，用于处理获取用户信息（/userinfo）时，解析jwt信息

```java
 /**
  * 配置jwt解码bean，用于处理获取用户信息（/userinfo）时，解析jwt信息
  */
 @Bean
 public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
 		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
 }

/**
 * 配置 jwt RSA公钥私钥，最终暴露到 jwkSetEndpoint("/oauth2/jwks") 节点
 */
@Bean
public JWKSource<SecurityContext> jwkSource() {
    JWK jwk = new RSAKey.Builder(authAuthorizationProperties.getPublicKey())
              .privateKey(authAuthorizationProperties.getPrivateKey())
              .keyUse(KeyUse.SIGNATURE)
              .algorithm(JWSAlgorithm.RS256)
              .keyID(authAuthorizationProperties.getKeyId())
              .build();
    JWKSet jwkSet = new JWKSet(jwk);
    return (jwkSelector, securityContext) -> {
    		return jwkSelector.select(jwkSet);
    };
}
```

配置Client客户端，注意配置的 clientId 、clientSecret 接入的客户端会使用，并且每个客户端使用独立的信息。

```
private RegisteredClient getRegisteredClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(UUID.randomUUID().toString())
                .clientSecret(UUID.randomUUID().toString())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.IMPLICIT)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri("http://127.0.0.1:8010/login/oauth2/code/toquery")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.ADDRESS)
                .scope(OidcScopes.PHONE)
                .scope("read")
                .scope("write")
                .clientSettings(
                        ClientSettings.builder()
                                //.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                                .requireAuthorizationConsent(false) // AUTHORIZATION_CODE是否需要点击同意
                                .build()
                )
                .tokenSettings(
                        TokenSettings.builder()
                                //使用透明方式，
                                // 默认是 OAuth2TokenFormat SELF_CONTAINED  全的jwt token
                                // REFERENCE 是引用方式，即使用jwt token，但是jwt token是通过oauth2 server生成的，而不是通过oauth2 client生成的
                                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                                // 授权码的有效期
                                .accessTokenTimeToLive(Duration.ofHours(1))
                                // 刷新token的有效期
                                .refreshTokenTimeToLive(Duration.ofDays(3))
                                .reuseRefreshTokens(true)
                                .build()
                )
                .build();
}

```

配置 `SecurityFilterChain` 权限 ， 可分为两个配置文件，**SecurityConfig** 和 **AuthorizationServerConfig** 

```
 @Bean
 public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
     http.formLogin(httpSecurityFormLoginConfigurer -> {
     });
     http.authorizeRequests(authorizeRequests -> {
     		authorizeRequests.anyRequest().authenticated();
     });
     return http.build();
 }
 
 // Spring Authorization Server 设置
 @Bean
 @Order(Ordered.HIGHEST_PRECEDENCE)
 public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
     // 获取用户信息
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

    http.formLogin(httpSecurityFormLoginConfigurer -> {
    });
    return http.build();
}

```

其他为 辅助配置

```
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }
    
    /**
     * 设置暴露的 Endpoint 地址信息
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer(authAuthorizationProperties.getIssuer())
//                .authorizationEndpoint("/oauth2/authorize")
//                .tokenEndpoint("/oauth2/token")
//                .jwkSetEndpoint("/oauth2/jwks")
//                .tokenRevocationEndpoint("/oauth2/revoke")
//                .tokenIntrospectionEndpoint("/oauth2/introspect")
//                .oidcClientRegistrationEndpoint("/connect/register")
//                .oidcUserInfoEndpoint("/userinfo")
                .build();
    }
```



