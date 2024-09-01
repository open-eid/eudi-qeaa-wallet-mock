package ee.ria.eudi.qeaa.wallet.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.JWTID;
import ee.ria.eudi.qeaa.wallet.configuration.properties.WalletProperties;
import ee.ria.eudi.qeaa.wallet.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class ClientAttestationPoPJwtFactory {
    public static final String JOSE_TYPE_WALLET_ATTESTATION_POP_JWT = "wallet-attestation-pop+jwt";
    private final ECDSASigner walletSigner;
    private final ECKey walletSigningKey;
    private final WalletProperties walletProperties;
    private final SignedJWT walletInstanceAttestation;

    public SignedJWT create(String audience) throws JOSEException, ParseException {
        JWTClaimsSet wiaPoPClaims = createClientAttestationPoPClaims(audience);
        JWSAlgorithm jwsAlgorithm = JwtUtil.getJwsAlgorithm(walletSigningKey.getCurve());
        SignedJWT walletInstanceAttestationPoP = new SignedJWT(new JWSHeader.Builder(jwsAlgorithm)
            .keyID(walletSigningKey.computeThumbprint().toString())
            .type(new JOSEObjectType(JOSE_TYPE_WALLET_ATTESTATION_POP_JWT))
            .build(), wiaPoPClaims);
        walletInstanceAttestationPoP.sign(walletSigner);
        return walletInstanceAttestationPoP;
    }

    private JWTClaimsSet createClientAttestationPoPClaims(String audience) throws ParseException {
        long requestObjectTtl = walletProperties.wallet().ttl().parRequestObject().toSeconds();
        Instant issuedAt = Instant.now();
        return new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, walletInstanceAttestation.getJWTClaimsSet().getStringClaim("sub"))
            .claim(JWTClaimNames.AUDIENCE, audience)
            .claim(JWTClaimNames.ISSUED_AT, issuedAt.getEpochSecond())
            .claim(JWTClaimNames.EXPIRATION_TIME, issuedAt.plusSeconds(requestObjectTtl).getEpochSecond())
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .build();
    }
}
