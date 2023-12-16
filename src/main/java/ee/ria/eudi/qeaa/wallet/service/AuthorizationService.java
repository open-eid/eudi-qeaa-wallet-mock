package ee.ria.eudi.qeaa.wallet.service;

import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import ee.ria.eudi.qeaa.wallet.model.ParResponse;
import ee.ria.eudi.qeaa.wallet.model.TokenResponse;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import java.text.ParseException;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;

@Service
@RequiredArgsConstructor
public class AuthorizationService {
    public static final String PAR_REQUEST_MAPPING = "http://eudi-as.localhost:12080/as/par";
    public static final String TOKEN_REQUEST_MAPPING = "http://eudi-as.localhost:12080/token";
    public static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";
    private final RestClient.Builder restClientBuilder;
    private final RestClientSsl ssl;
    private final SignedJWT walletInstanceAttestation;
    private RestClient restClient;

    @PostConstruct
    private void setupRestClient() {
        restClient = restClientBuilder.apply(ssl.fromBundle("eudi-wallet")).build();
    }

    public ParResponse pushedAuthorizationRequest(SignedJWT requestObject,
                                                  SignedJWT clientAttestation,
                                                  SignedJWT clientAttestationPoP) {
        var payload = new LinkedMultiValueMap<>();
        payload.add("request", requestObject.serialize());
        payload.add("client_assertion_type", CLIENT_ASSERTION_TYPE);
        payload.add("client_assertion", clientAttestation.serialize() + "~" + clientAttestationPoP.serialize());
        return restClient.post()
            .uri(PAR_REQUEST_MAPPING) // TODO: From metadata
            .body(payload)
            .contentType(APPLICATION_FORM_URLENCODED)
            .accept(APPLICATION_JSON)
            .retrieve()
            .body(ParResponse.class);
    }

    public TokenResponse tokenRequest(String code,
                                      CodeVerifier codeVerifier,
                                      SignedJWT dPoPProof,
                                      SignedJWT clientAttestation,
                                      SignedJWT clientAttestationPoP,
                                      String redirectUri
    ) throws ParseException {
        String wiaSubject = walletInstanceAttestation.getJWTClaimsSet().getStringClaim(JWTClaimNames.SUBJECT);
        var payload = new LinkedMultiValueMap<>();
        payload.add("client_id", wiaSubject);
        payload.add("grant_type", "authorization_code");
        payload.add("code", code);
        payload.add("code_verifier", codeVerifier.getValue());
        payload.add("client_assertion_type", CLIENT_ASSERTION_TYPE);
        payload.add("client_assertion", clientAttestation.serialize() + "~" + clientAttestationPoP.serialize());
        payload.add("redirect_uri", redirectUri);
        return restClient.post()
            .uri(TOKEN_REQUEST_MAPPING) // TODO: From metadata
            .header("DPoP", dPoPProof.serialize())
            .body(payload)
            .contentType(APPLICATION_FORM_URLENCODED)
            .accept(APPLICATION_JSON)
            .retrieve()
            .body(TokenResponse.class);
    }
}
