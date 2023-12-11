package ee.ria.eudi.qeaa.wallet.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import ee.ria.eudi.qeaa.wallet.util.MDocUtil;
import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.cert.X509Certificate;
import java.util.List;

@Configuration
public class MDocConfiguration {

    @Bean
    public SimpleCOSECryptoProvider deviceCryptoProvider(ECKey walletSigningKey, X509Certificate walletSigningCert) throws JOSEException {
        COSECryptoProviderKeyInfo deviceCryptoProviderKeyInfo = new COSECryptoProviderKeyInfo(
            MDocUtil.KEY_ID_DEVICE,
            MDocUtil.getAlgorithmId(walletSigningCert.getPublicKey()),
            walletSigningCert.getPublicKey(),
            walletSigningKey.toPrivateKey(),
            List.of(),
            List.of());
        return new SimpleCOSECryptoProvider(List.of(deviceCryptoProviderKeyInfo));
    }
}
