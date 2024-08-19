package ee.ria.eudi.qeaa.wallet.util;

import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.model.VerifierMetadata;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.NotImplementedException;

import java.io.IOException;
import java.text.ParseException;

@UtilityClass
public class JwtUtil {

    public JWSAlgorithm getJwsAlgorithm(Curve curve) {
        if (curve.equals(Curve.P_256)) {
            return JWSAlgorithm.ES256;
        } else if (curve.equals(Curve.SECP256K1)) {
            return JWSAlgorithm.ES256K;
        } else if (curve.equals(Curve.P_384)) {
            return JWSAlgorithm.ES384;
        } else if (curve.equals(Curve.P_521)) {
            return JWSAlgorithm.ES512;
        } else {
            throw new IllegalArgumentException("Unsupported curve");
        }
    }

    @SneakyThrows
    public JWEEncrypter getJWEEncrypter(JWK jwk) {
        if (jwk.getKeyType() == KeyType.RSA) {
            return new RSAEncrypter(jwk.toRSAKey());
        } else if (jwk.getKeyType() == KeyType.EC) {
            return new ECDHEncrypter(jwk.toECKey());
        } else {
            throw new NotImplementedException("Encrypter for key type not implemented: " + jwk.getKeyType());
        }
    }

    public JWKSet getJwkSet(VerifierMetadata verifierMetadata) {
        try {
            if (verifierMetadata.getJwks() != null && !verifierMetadata.getJwks().isEmpty()) {
                return JWKSet.parse(verifierMetadata.getJwks());
            } else {
                return JWKSet.load(verifierMetadata.getJwksUri());
            }
        } catch (ParseException | IOException e) {
            throw new WalletException("Invalid verifier metadata", e);
        }
    }
}
