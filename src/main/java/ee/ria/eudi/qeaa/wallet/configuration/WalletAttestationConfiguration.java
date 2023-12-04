package ee.ria.eudi.qeaa.wallet.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.wallet.util.JwtUtil;
import ee.ria.eudi.qeaa.wallet.util.X509CertUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Configuration
public class WalletAttestationConfiguration {
    public static final String JOSE_TYPE_WALLET_ATTESTATION_JWT = "wallet-attestation+jwt";

    @Bean
    public SignedJWT walletInstanceAttestation(ECKey walletProviderSigningKey, ECKey walletSigningKey, X509Certificate walletSigningCert, X509Certificate walletProviderSigningCert) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, X509CertUtil.getSubjectAlternativeNameDNSName(walletProviderSigningCert))
            .claim(JWTClaimNames.SUBJECT, X509CertUtil.getSubjectAlternativeNameDNSName(walletSigningCert)) // TODO: Should this be the thumbprint of the JWK in the cnf parameter?
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim(JWTClaimNames.EXPIRATION_TIME, Instant.now().plus(356, ChronoUnit.DAYS).getEpochSecond())
            .claim("cnf", Map.of("jwk", walletSigningKey.toJSONObject()))
            .build();

        Curve curve = walletProviderSigningKey.getCurve();
        JWSAlgorithm alg = JwtUtil.getJwsAlgorithm(curve);
        JWSHeader jwsHeader = new JWSHeader.Builder(alg)
            .keyID(walletProviderSigningKey.getKeyID())
            .type(new JOSEObjectType(JOSE_TYPE_WALLET_ATTESTATION_JWT))
            .x509CertChain(walletProviderSigningKey.getX509CertChain())
            .x509CertSHA256Thumbprint(walletProviderSigningKey.getX509CertSHA256Thumbprint())
            .build();

        JWSSigner signer = new ECDSASigner(walletProviderSigningKey);
        SignedJWT walletAttestation = new SignedJWT(jwsHeader, claimsSet);
        walletAttestation.sign(signer);
        return walletAttestation;
    }
}
