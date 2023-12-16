package ee.ria.eudi.qeaa.wallet.controller;

import ee.ria.eudi.qeaa.wallet.error.WalletException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.wallet.factory.DPoPFactory;
import ee.ria.eudi.qeaa.wallet.factory.ClientAttestationPoPJwtFactory;
import ee.ria.eudi.qeaa.wallet.model.Session;
import ee.ria.eudi.qeaa.wallet.model.TokenResponse;
import ee.ria.eudi.qeaa.wallet.repository.SessionRepository;
import ee.ria.eudi.qeaa.wallet.service.AuthorizationService;
import ee.ria.eudi.qeaa.wallet.validation.AccessTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.text.ParseException;

@Slf4j
@Controller
@RequiredArgsConstructor
public class CredentialCallbackController {
    public static final String ISSUANCE_CALLBACK_REQUEST_MAPPING = "/issuance_callback";
    private final DPoPFactory dPoPFactory;
    private final AccessTokenValidator accessTokenValidator;
    private final AuthorizationService authorizationService;
    private final ClientAttestationPoPJwtFactory clientAttestationPoPJwtFactory;
    private final SessionRepository sessionRepository;
    private final SignedJWT walletInstanceAttestation;

    @GetMapping(ISSUANCE_CALLBACK_REQUEST_MAPPING)
    public ModelAndView issuanceRequestCallback(@RequestParam(name = "state") String state,
                                                @RequestParam(name = "code") String code) throws JOSEException, ParseException {
        Session session = sessionRepository.findByState(state);
        if (session == null) {
            throw new WalletException("Session not found");
        }
        String tokenEndpoint = "http://eudi-as.localhost:12080/token"; // TODO: From metadata
        SignedJWT tokenDPoPProof = dPoPFactory.create(HttpMethod.POST, tokenEndpoint);
        SignedJWT walletInstanceAttestationPoP = clientAttestationPoPJwtFactory.create(tokenEndpoint);
        TokenResponse tokenResponse = authorizationService.tokenRequest(code, session.getCodeVerifier(), tokenDPoPProof,
            walletInstanceAttestation, walletInstanceAttestationPoP, session.getRedirectUri());
        SignedJWT accessToken = accessTokenValidator.validate(tokenResponse);
        return new ModelAndView("forward:/");
    }
}
