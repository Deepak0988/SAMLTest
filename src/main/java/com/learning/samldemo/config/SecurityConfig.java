package com.learning.samldemo.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
@Slf4j
public class SecurityConfig {

    @Autowired
    LoginSuccessHandler loginSuccessHandler;

    @Autowired
    CustomLogoutFilter customLogoutFilter;

    @Bean
    SecurityFilterChain web(HttpSecurity http, RelyingPartyRegistrationRepository registrations) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .antMatchers(HttpMethod.GET, "/logoutSuccess").permitAll()
                        .anyRequest().authenticated()
                )
                .saml2Login(withDefaults())
                .saml2Logout(withDefaults());
        http
                .csrf().disable();
        http.saml2Login().successHandler(loginSuccessHandler);
       // http.addFilterBefore(customLogoutFilter, LogoutFilter.class);
        return http.build();
    }

    @Bean
    protected RelyingPartyRegistrationRepository relyingPartyRegistrations() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeySpecException {

        CertificateFactory certificateFactory = CertificateFactory
                .getInstance("X.509");
        FileInputStream in = new FileInputStream(ResourceUtils.getFile("classpath:local.crt"));

        X509Certificate cert = (X509Certificate) certificateFactory
                .generateCertificate(in);
        in.close();

        String key = new String(Files.readAllBytes(ResourceUtils.getFile("classpath:local.key").toPath()), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.decodeBase64(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        RSAPrivateKey privateKey =  (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        Saml2X509Credential credential = Saml2X509Credential.signing(privateKey, cert);


        File verificationKeyAP = ResourceUtils.getFile("classpath:saml-certificate/okta.cert");
        X509Certificate certificateAP = X509Support.decodeCertificate(verificationKeyAP);
        Saml2X509Credential credentialAP = Saml2X509Credential.verification(certificateAP);

        RelyingPartyRegistration registration= RelyingPartyRegistrations
                .fromMetadataLocation("classpath:metadata.xml")
                .registrationId("okta-saml")
                .singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT)
                .singleLogoutServiceLocation("https://dev-757575.okta.com/app/dev-757575_samltestapp_1/exk7q6kaa93M3Q37l4x7/slo/saml")
                .signingX509Credentials((signing) -> signing.add(credential))
                .assertingPartyDetails(party -> party
                        .entityId("http://www.okta.com/exk7q6kaa93M3Q37l4x7")
                        .singleSignOnServiceLocation("https://dev-757575.okta.com/app/dev-757575_samltestapp_1/exk7q6kaa93M3Q37l4x7/sso/saml")
                        .wantAuthnRequestsSigned(false)
                        .verificationX509Credentials(c -> c.add(credentialAP)))
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }
}
