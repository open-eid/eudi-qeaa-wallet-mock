package ee.ria.eudi.qeaa.wallet.factory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.wallet.configuration.properties.WalletProperties;
import ee.ria.eudi.qeaa.wallet.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class CredentialJwtKeyProofFactory {
    public static final String JOSE_TYPE_OPENID4VCI_PROOF_JWT = "openid4vci-proof+jwt";
    private final ECKey walletSigningKey;
    private final SignedJWT walletInstanceAttestation;
    private final ECDSASigner walletSigner;
    private final WalletProperties walletProperties;

    public SignedJWT create(String cNonce) throws JOSEException, ParseException {
        JWSAlgorithm jwsAlgorithm = JwtUtil.getJwsAlgorithm(walletSigningKey.getCurve());
        SignedJWT jwtKeyProof = new SignedJWT(new JWSHeader.Builder(jwsAlgorithm)
            .type(new JOSEObjectType(JOSE_TYPE_OPENID4VCI_PROOF_JWT))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), getCredentialJwtKeyProofClaims(cNonce));
        jwtKeyProof.sign(walletSigner);
        return jwtKeyProof;
    }

    private JWTClaimsSet getCredentialJwtKeyProofClaims(String cNonce) throws ParseException {
        return new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, walletInstanceAttestation.getJWTClaimsSet().getStringClaim("sub"))
            .claim(JWTClaimNames.AUDIENCE, walletProperties.issuer().baseUrl())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("nonce", cNonce)
            .build();
    }
}
