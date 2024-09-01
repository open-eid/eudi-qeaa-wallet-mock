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
import ee.ria.eudi.qeaa.wallet.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class DPoPFactory {
    public static final String JOSE_OBJECT_TYPE_DPOP_JWT = "dpop+jwt";
    private final ECKey walletSigningKey;
    private final ECDSASigner walletSigner;

    public SignedJWT create(HttpMethod htm, String htu) throws JOSEException {
        return create(htm, htu, null);
    }

    public SignedJWT create(HttpMethod htm, String htu, String ath) throws JOSEException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("htm", htm.name())
            .claim("htu", htu);
        if (ath != null) {
            claimsBuilder.claim("ath", ath);
        }

        JWSAlgorithm jwsAlgorithm = JwtUtil.getJwsAlgorithm(walletSigningKey.getCurve());
        JWSHeader header = new JWSHeader.Builder(jwsAlgorithm)
            .type(new JOSEObjectType(JOSE_OBJECT_TYPE_DPOP_JWT))
            .jwk(walletSigningKey.toPublicJWK())
            .build();
        SignedJWT jwtKeyProof = new SignedJWT(header, claimsBuilder.build());
        jwtKeyProof.sign(walletSigner);
        return jwtKeyProof;
    }
}
