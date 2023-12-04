package ee.ria.eudi.qeaa.wallet.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import lombok.experimental.UtilityClass;

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
}
