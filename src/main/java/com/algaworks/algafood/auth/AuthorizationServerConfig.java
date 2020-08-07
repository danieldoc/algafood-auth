package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        final int UMA_HORA_SEGUNDOS = 60 * 60;
        final int UM_DIA_SEGUNDOS = UMA_HORA_SEGUNDOS * 24;

        clients
                .inMemory()
                    .withClient("algafood-web-client")
                    .secret(passwordEncoder.encode("web123"))
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("write", "read")
                    .accessTokenValiditySeconds(UMA_HORA_SEGUNDOS * 6) // 6 horas
                    .refreshTokenValiditySeconds(UM_DIA_SEGUNDOS * 15) // 15 dias

//                http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=http://analytics.algafood.com

//                PKCE
//                Plain
//                http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=http://analytics.algafood.com&code_challenge=teste1234&code_challenge_method=plain
//                SH256
//                http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=http://analytics.algafood.com&code_challenge=teste1234&code_challenge_method=s256
                .and()
                    .withClient("foodanalytics")
                    .secret(passwordEncoder.encode(""))
                    .authorizedGrantTypes("authorization_code")
                    .scopes("write", "read")
                    .redirectUris("http://analytics.algafood.com")

                // http://localhost:8081/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://web-client.com
                .and()
                    .withClient("webadmin")
                    .authorizedGrantTypes("implicit")
                    .scopes("write", "read")
                    .redirectUris("http://web-client.com")

                .and()
                    .withClient("faturamento")
                    .secret(passwordEncoder.encode("faturamento123"))
                    .authorizedGrantTypes("client_credentials")
                    .scopes("write", "read")

                .and()
                    .withClient("check-token")
                    .secret(passwordEncoder.encode("123web"));
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//        security.checkTokenAccess("isAuthenticated()");
        security.checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenGranter(tokenGranter(endpoints));
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();

        jwtAccessTokenConverter.setSigningKey("algaworks");

        return jwtAccessTokenConverter;
    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }
}
