package ee.ria.eudi.qeaa.wallet.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.factory.ClientAttestationPoPJwtFactory;
import ee.ria.eudi.qeaa.wallet.factory.CredentialJwtKeyProofFactory;
import ee.ria.eudi.qeaa.wallet.factory.DPoPFactory;
import ee.ria.eudi.qeaa.wallet.model.AuthorizationDetails;
import ee.ria.eudi.qeaa.wallet.model.Credential;
import ee.ria.eudi.qeaa.wallet.model.Credential.CredentialBuilder;
import ee.ria.eudi.qeaa.wallet.model.CredentialRequest;
import ee.ria.eudi.qeaa.wallet.model.CredentialResponse;
import ee.ria.eudi.qeaa.wallet.model.Session;
import ee.ria.eudi.qeaa.wallet.model.TokenResponse;
import ee.ria.eudi.qeaa.wallet.repository.CredentialRepository;
import ee.ria.eudi.qeaa.wallet.repository.SessionRepository;
import ee.ria.eudi.qeaa.wallet.service.AuthorizationService;
import ee.ria.eudi.qeaa.wallet.service.CredentialIssuerService;
import ee.ria.eudi.qeaa.wallet.service.MetadataService;
import ee.ria.eudi.qeaa.wallet.util.AccessTokenUtil;
import ee.ria.eudi.qeaa.wallet.validation.AccessTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Controller
@RequiredArgsConstructor
public class CredentialCallbackController {
    public static final String ISSUANCE_CALLBACK_REQUEST_MAPPING = "/issuance_callback";
    private final DPoPFactory dPoPFactory;
    private final AccessTokenValidator accessTokenValidator;
    private final AuthorizationService authorizationService;
    private final ClientAttestationPoPJwtFactory clientAttestationPoPJwtFactory;
    private final CredentialIssuerService credentialIssuerService;
    private final CredentialJwtKeyProofFactory credentialJwtKeyProofFactory;
    private final CredentialRepository credentialRepository;
    private final SessionRepository sessionRepository;
    private final SignedJWT walletInstanceAttestation;
    private final MetadataService metadataService;

    @GetMapping(ISSUANCE_CALLBACK_REQUEST_MAPPING)
    public ModelAndView issuanceRequestCallback(@RequestParam(name = "state") String state,
                                                @RequestParam(name = "code") String code) throws JOSEException, ParseException {
        Session session = sessionRepository.findByState(state).orElseThrow(() -> new WalletException("Session not found"));
        SignedJWT tokenDPoPProof = dPoPFactory.create(HttpMethod.POST, metadataService.getAuthorizationServerMetadata().tokenEndpoint());
        SignedJWT walletInstanceAttestationPoP = clientAttestationPoPJwtFactory.create(metadataService.getAuthorizationServerMetadata().tokenEndpoint());
        TokenResponse tokenResponse = authorizationService.tokenRequest(code, session.getCodeVerifier(), tokenDPoPProof,
            walletInstanceAttestation, walletInstanceAttestationPoP, session.getRedirectUri());

        SignedJWT accessToken = accessTokenValidator.validate(tokenResponse);
        String accessTokenHash = AccessTokenUtil.computeSHA256(tokenResponse.accessToken());
        SignedJWT credentialDPoPProof = dPoPFactory.create(HttpMethod.POST, metadataService.getCredentialIssuerMetadata().credentialEndpoint(), accessTokenHash);
        SignedJWT credentialJwtKeyProof = credentialJwtKeyProofFactory.create(tokenResponse.cNonce());
        AuthorizationDetails authorizationDetails = getAuthorizationDetails(session);
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof, authorizationDetails);
        CredentialResponse credentialResponse = credentialIssuerService.credentialRequest(accessToken, credentialDPoPProof, credentialRequest);

        saveCredential(authorizationDetails, accessToken, tokenResponse, credentialResponse);
        return new ModelAndView("forward:/");
    }

    private AuthorizationDetails getAuthorizationDetails(Session session) {
        List<AuthorizationDetails> authorizationDetailsList = session.getAuthorizationDetails();
        if (authorizationDetailsList.size() != 1) {
            throw new NotImplementedException("Multiple authorization details processing not supported");
        }
        return authorizationDetailsList.getFirst();
    }

    private CredentialRequest getCredentialRequest(SignedJWT credentialJwtKeyProof, AuthorizationDetails authorizationDetails) {
        CredentialRequest.Proof jwtProof = CredentialRequest.Proof.builder()
            .proofType("jwt")
            .jwt(credentialJwtKeyProof.serialize())
            .build();
        return CredentialRequest.builder()
            .format(authorizationDetails.getFormat())
            .doctype(authorizationDetails.getDoctype())
            .proof(jwtProof)
            .build();
    }

    private void saveCredential(AuthorizationDetails authorizationDetails, SignedJWT accessToken, TokenResponse tokenResponse, CredentialResponse credentialResponse) {
        CredentialBuilder credentialBuilder = Credential.builder()
            .format(authorizationDetails.getFormat())
            .doctype(authorizationDetails.getDoctype())
            .value(credentialResponse.credential())
            .issuedAt(LocalDateTime.now())
            .accessToken(accessToken.serialize())
            .cNonce(tokenResponse.cNonce())
            .cNonceExpiresIn(tokenResponse.cNonceExpiresIn());
        if (credentialResponse.cNonce() != null) {
            credentialBuilder.cNonce(credentialResponse.cNonce());
            credentialBuilder.cNonceExpiresIn(credentialResponse.cNonceExpiresIn());
        }
        credentialRepository.save(credentialBuilder.build());
    }
}
