package ee.ria.eudi.qeaa.wallet.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import ee.ria.eudi.qeaa.wallet.configuration.properties.WalletProperties;
import ee.ria.eudi.qeaa.wallet.service.MetadataService;
import ee.ria.eudi.qeaa.wallet.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static ee.ria.eudi.qeaa.wallet.controller.CredentialCallbackController.ISSUANCE_CALLBACK_REQUEST_MAPPING;

@Component
@RequiredArgsConstructor
public class AuthorizationRequestObjectFactory {
    private final ECKey walletSigningKey;
    private final ECDSASigner walletSigner;
    private final WalletProperties walletProperties;
    private final MetadataService metadataService;
    private final SignedJWT walletInstanceAttestation;

    public SignedJWT create(CodeVerifier codeVerifier, Map<String, Object> authorizationDetails) throws ParseException, JOSEException {
        long requestObjectTtl = walletProperties.wallet().ttl().parRequestObject().toSeconds();
        String wiaSubject = walletInstanceAttestation.getJWTClaimsSet().getStringClaim(JWTClaimNames.SUBJECT);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, wiaSubject)
            .claim(JWTClaimNames.AUDIENCE, metadataService.getAuthorizationServerMetadata().pushedAuthorizationRequestEndpoint())
            .claim(JWTClaimNames.EXPIRATION_TIME, Instant.now().plusSeconds(requestObjectTtl).getEpochSecond())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .claim("state", new State().getValue())
            .claim("code_challenge", CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier).getValue())
            .claim("code_challenge_method", CodeChallengeMethod.S256.getValue())
            .claim("client_id", wiaSubject)
            .claim("authorization_details", List.of(authorizationDetails))
            .claim("response_type", "code")
            .claim("redirect_uri", walletProperties.wallet().baseUrl() + ISSUANCE_CALLBACK_REQUEST_MAPPING)
            .build();

        SignedJWT requestObject = new SignedJWT(new JWSHeader.Builder(JwtUtil.getJwsAlgorithm(walletSigningKey.getCurve()))
            .keyID(walletSigningKey.computeThumbprint().toString())
            .type(JOSEObjectType.JWT)
            .build(), claims);
        requestObject.sign(walletSigner);
        return requestObject;
    }
}
