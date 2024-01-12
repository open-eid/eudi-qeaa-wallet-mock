package ee.ria.eudi.qeaa.wallet.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.model.TokenResponse;
import ee.ria.eudi.qeaa.wallet.service.MetadataService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;

@Component
@RequiredArgsConstructor
public class AccessTokenValidator {
    public static final String TOKEN_TYPE_DPOP = "DPoP";
    private final MetadataService metadataService;
    private final SignedJWT walletInstanceAttestation;
    private final ECKey walletSigningKey;

    public SignedJWT validate(TokenResponse tokenResponse) {
        try {
            if (!TOKEN_TYPE_DPOP.equals(tokenResponse.tokenType())) {
                throw new WalletException("Invalid access token type");
            }
            SignedJWT accessToken = SignedJWT.parse(tokenResponse.accessToken());
            JWKSet jwkSet = metadataService.getAuthorizationServerJWKSet();
            ImmutableJWKSet<SecurityContext> immutableJWKSet = new ImmutableJWKSet<>(jwkSet);
            JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(accessToken.getHeader().getAlgorithm(), immutableJWKSet);
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsKeySelector);
            jwtProcessor.setJWTClaimsSetVerifier(getClaimsVerifier());
            jwtProcessor.process(accessToken, null);
            return accessToken;
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new WalletException("Invalid access token", ex);
        }
    }

    private DefaultJWTClaimsVerifier<SecurityContext> getClaimsVerifier() throws ParseException, JOSEException {
        return new AccessTokenClaimsVerifier<>(metadataService.getAuthorizationServerMetadata().issuer(),
            metadataService.getCredentialIssuerMetadata().credentialIssuer(),
            walletInstanceAttestation.getJWTClaimsSet().getStringClaim("sub"),
            walletSigningKey.computeThumbprint().toString());
    }
}
