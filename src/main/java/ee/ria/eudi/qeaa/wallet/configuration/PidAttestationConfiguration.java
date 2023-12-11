package ee.ria.eudi.qeaa.wallet.configuration;

import COSE.OneKey;
import com.nimbusds.jose.jwk.ECKey;
import ee.ria.eudi.qeaa.wallet.model.Credential;
import ee.ria.eudi.qeaa.wallet.repository.CredentialRepository;
import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.dataelement.DEFullDateMode;
import id.walt.mdoc.dataelement.DataElement;
import id.walt.mdoc.dataelement.FullDateElement;
import id.walt.mdoc.dataelement.MapElement;
import id.walt.mdoc.dataelement.StringElement;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.doc.MDocBuilder;
import id.walt.mdoc.mso.DeviceKeyInfo;
import id.walt.mdoc.mso.ValidityInfo;
import kotlinx.datetime.Clock;
import kotlinx.datetime.Instant;
import kotlinx.datetime.LocalDate;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static ee.ria.eudi.qeaa.wallet.model.Credential.CREDENTIAL_FORMAT_MSO_MDOC;

@Configuration
@RequiredArgsConstructor
public class PidAttestationConfiguration {
    public static final String DOCTYPE_EU_EUROPA_EC_EUDI_PID_1 = "eu.europa.ec.eudi.pid.1";
    public static final String NAMESPACE_EU_EUROPA_EC_EUDI_PID_1 = "eu.europa.ec.eudi.pid.1";
    public static final String NAMESPACE_EU_EUROPA_EC_EUDI_PID_EE_1 = "eu.europa.ec.eudi.pid.ee.1";
    public static final String KEY_ID_ISSUER = "issuer-key-id";
    private final ECKey walletSigningKey;

    @Bean
    public SimpleCOSECryptoProvider issuerCryptoProvider(SslBundles sslBundles) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        KeyPair issuerKey = getIssuerKey(sslBundles);
        if (issuerKey.getPublic() instanceof ECPublicKey ecPublicKey) {
            return new SimpleCOSECryptoProvider(List.of(new COSECryptoProviderKeyInfo(KEY_ID_ISSUER, getAlgorithmId(ecPublicKey),
                ecPublicKey, issuerKey.getPrivate(), getIssuerCertificateChain(sslBundles), Collections.emptyList())));
        } else {
            throw new IllegalArgumentException("Invalid key type. An Elliptic Curve key is required by ISO/IEC 18013-5:2021.");
        }
    }

    @Bean
    public MDoc pidAttestation(SimpleCOSECryptoProvider issuerCryptoProvider) {
        ValidityInfo validityInfo = getValidityInfo();
        DeviceKeyInfo deviceKeyInfo = getDeviceKeyInfo();
        MDocBuilder mDocBuilder = new MDocBuilder(DOCTYPE_EU_EUROPA_EC_EUDI_PID_1);
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "family_name", new StringElement("Mari-Liis"));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "given_name", new StringElement("Männik"));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "birth_date", getFullDateElement(1979, 12, 24));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "issuance_date", getFullDateElement(2024, 1, 1));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "expiry_date", getFullDateElement(2032, 1, 1));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "issuing_authority", new StringElement("PPA"));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "issuing_country", new StringElement("EE"));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1, "document_number", new StringElement("KE1234567"));
        mDocBuilder.addItemToSign(NAMESPACE_EU_EUROPA_EC_EUDI_PID_EE_1, "personal_identification_number", new StringElement("60001019906"));
        return mDocBuilder.sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, KEY_ID_ISSUER);
    }

    @Bean
    public CommandLineRunner persistPidAttestation(MDoc pidAttestation, CredentialRepository credentialRepository) {
        return args -> {
            Credential credential = Credential.builder()
                .format(CREDENTIAL_FORMAT_MSO_MDOC)
                .doctype(NAMESPACE_EU_EUROPA_EC_EUDI_PID_1)
                .value(pidAttestation.toCBORHex())
                .issuedAt(LocalDateTime.now())
                .build();
            credentialRepository.save(credential);
        };
    }

    private FullDateElement getFullDateElement(int year, int month, int day) {
        return new FullDateElement(new LocalDate(year, month, day), DEFullDateMode.full_date_str);
    }

    public KeyPair getIssuerKey(SslBundles sslBundles) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        SslBundle bundle = sslBundles.getBundle("eudi-issuer");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        Key key = keyStore.getKey(bundle.getKey().getAlias(), null);
        X509Certificate issuerCert = (X509Certificate) keyStore.getCertificate(bundle.getKey().getAlias());
        return new KeyPair(issuerCert.getPublicKey(), (PrivateKey) key);
    }


    public List<X509Certificate> getIssuerCertificateChain(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-issuer");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        Certificate[] certificateChain = keyStore.getCertificateChain(bundle.getKey().getAlias());
        return Arrays.stream(certificateChain).map(c -> (X509Certificate) c).toList();
    }

    private ValidityInfo getValidityInfo() {
        Instant signedAt = Clock.System.INSTANCE.now();
        Instant validTo = Instant.Companion.fromEpochSeconds(signedAt.getEpochSeconds() + Duration.ofDays(3650).toSeconds(), 0);
        return new ValidityInfo(signedAt, signedAt, validTo, null);
    }

    @SneakyThrows
    private DeviceKeyInfo getDeviceKeyInfo() {
        OneKey key = new OneKey(walletSigningKey.toPublicKey(), null);
        MapElement deviceKeyDataElement = DataElement.Companion.fromCBOR(key.AsCBOR().EncodeToBytes());
        return new DeviceKeyInfo(deviceKeyDataElement, null, null);
    }

    private AlgorithmID getAlgorithmId(ECPublicKey ecPublicKey) {
        int bitLength = ecPublicKey.getParams().getOrder().bitLength();
        return switch (bitLength) {
            case 256 -> AlgorithmID.ECDSA_256;
            case 384 -> AlgorithmID.ECDSA_384;
            case 521 -> AlgorithmID.ECDSA_512;
            default -> throw new IllegalArgumentException("Unsupported key size: " + bitLength);
        };
    }
}
