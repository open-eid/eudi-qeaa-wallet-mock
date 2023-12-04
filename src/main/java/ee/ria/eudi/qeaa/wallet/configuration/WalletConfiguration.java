package ee.ria.eudi.qeaa.wallet.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

@Configuration
@ConfigurationPropertiesScan
public class WalletConfiguration {

    @Bean
    public X509Certificate walletSigningCert(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-wallet");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        return (X509Certificate) keyStore.getCertificate(bundle.getKey().getAlias());
    }

    @Bean
    public ECKey walletSigningKey(SslBundles sslBundles) throws KeyStoreException, JOSEException {
        SslBundle bundle = sslBundles.getBundle("eudi-wallet");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        SslBundleKey bundleKey = bundle.getKey();
        String password = bundleKey.getPassword();
        return ECKey.load(keyStore, bundleKey.getAlias(), password != null ? password.toCharArray() : null);
    }

    @Bean
    public ECDSASigner walletSigner(ECKey walletSigningKey) throws JOSEException {
        return new ECDSASigner(walletSigningKey);
    }

    @Bean
    public X509Certificate walletProviderSigningCert(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-wallet-provider");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        return (X509Certificate) keyStore.getCertificate(bundle.getKey().getAlias());
    }

    @Bean
    public ECKey walletProviderSigningKey(SslBundles sslBundles) throws KeyStoreException, JOSEException {
        SslBundle bundle = sslBundles.getBundle("eudi-wallet-provider");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        SslBundleKey bundleKey = bundle.getKey();
        String password = bundleKey.getPassword();
        return ECKey.load(keyStore, bundleKey.getAlias(), password != null ? password.toCharArray() : null);
    }
}
