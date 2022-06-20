package com.learning.samldemo.config;

import org.opensaml.security.x509.X509Support;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Service
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    public SecurityConfig(@Lazy RelyingPartyRegistrationRepository relyingPartyRegistrationRepository){
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize ->
                        authorize.anyRequest().authenticated()
                ).saml2Login();

        // add auto-generation of ServiceProvider Metadata
        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());
        http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
    }


    @Bean
    protected RelyingPartyRegistrationRepository relyingPartyRegistrations() throws CertificateException, FileNotFoundException {
        File verificationKey = ResourceUtils.getFile("classpath:saml-certificate/okta.cert");
        X509Certificate certificate = X509Support.decodeCertificate(verificationKey);
        Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId("okta-saml")
                .assertingPartyDetails(party -> party
                        .entityId("http://www.okta.com/exk7q6kaa93M3Q37l4x7")
                        .singleSignOnServiceLocation("https://dev-757575.okta.com/app/dev-757575_samltestapp_1/exk7q6kaa93M3Q37l4x7/sso/saml")
                        .wantAuthnRequestsSigned(false)
                        .verificationX509Credentials(c -> c.add(credential))
                ).build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }



}
