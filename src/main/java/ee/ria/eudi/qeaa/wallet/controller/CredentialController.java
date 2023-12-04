package ee.ria.eudi.qeaa.wallet.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import ee.ria.eudi.qeaa.wallet.configuration.properties.WalletProperties;
import ee.ria.eudi.qeaa.wallet.factory.AuthorizationRequestObjectFactory;
import ee.ria.eudi.qeaa.wallet.factory.ClientAttestationPoPJwtFactory;
import ee.ria.eudi.qeaa.wallet.model.ParResponse;
import ee.ria.eudi.qeaa.wallet.model.Session;
import ee.ria.eudi.qeaa.wallet.repository.SessionRepository;
import ee.ria.eudi.qeaa.wallet.service.AuthorizationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static ee.ria.eudi.qeaa.wallet.model.Credential.CREDENTIAL_FORMAT_MSO_MDOC;

@Slf4j
@Controller
@RequiredArgsConstructor
public class CredentialController {
    private final AuthorizationRequestObjectFactory authorizationRequestObjectFactory;
    private final AuthorizationService authorizationService;
    private final ClientAttestationPoPJwtFactory clientAttestationPoPJwtFactory;
    private final SessionRepository sessionRepository;
    private final SignedJWT walletInstanceAttestation;
    private final WalletProperties walletProperties;

    @GetMapping("/")
    public ModelAndView credentialsView() {
        return new ModelAndView("credentials");
    }

    @PostMapping(value = "/credential")
    public RedirectView requestCredential() throws JOSEException, ParseException {
        CodeVerifier codeVerifier = new CodeVerifier();
        SignedJWT requestObject = authorizationRequestObjectFactory.create(codeVerifier, getAuthorizationDetails());
        SignedJWT walletInstanceAttestationPoP = clientAttestationPoPJwtFactory.create("http://eudi-as.localhost:12080/as/par"); // TODO: From metadata
        ParResponse parResponse = authorizationService.pushedAuthorizationRequest(requestObject, walletInstanceAttestation, walletInstanceAttestationPoP);
        sessionRepository.save(Session.builder()
            .requestObjectClaims(requestObject.getJWTClaimsSet())
            .codeVerifier(codeVerifier)
            .build());

        String wiaSubject = walletInstanceAttestation.getJWTClaimsSet().getStringClaim(JWTClaimNames.SUBJECT);
        return new RedirectView(UriComponentsBuilder
            .fromUriString("http://eudi-as.localhost:12080/authorize") // TODO: From metadata
            .queryParam("request_uri", parResponse.requestUri())
            .queryParam("client_id", wiaSubject)
            .toUriString());
    }

    private Map<String, Object> getAuthorizationDetails() {
        return Map.of(
            "type", "openid_credential",
            "format", CREDENTIAL_FORMAT_MSO_MDOC,
            "doctype", "org.iso.18013.5.1.mDL",
            "locations", List.of(walletProperties.issuer().baseUrl())
        );
    }
}
