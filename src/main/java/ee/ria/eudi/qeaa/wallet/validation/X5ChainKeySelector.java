package ee.ria.eudi.qeaa.wallet.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.X509CertChainUtils;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.util.X509CertUtil;
import lombok.RequiredArgsConstructor;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

@RequiredArgsConstructor
public class X5ChainKeySelector implements JWSKeySelector<SecurityContext> {
    private final String subjectAlternativeNameDNSName;
    private final Set<JWSAlgorithm> acceptedJWSAlgorithms;
    private final KeyStore trustStore;

    @Override
    public List<? extends Key> selectJWSKeys(JWSHeader header, SecurityContext context) throws KeySourceException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!acceptedJWSAlgorithms.contains(alg)) {
            throw new KeySourceException("JWS header algorithm not accepted: " + alg);
        }
        X509Certificate candidateKey = getCandidateKey(header);
        return List.of(candidateKey.getPublicKey());
    }

    private X509Certificate getCandidateKey(JWSHeader header) throws KeySourceException {
        try {
            List<X509Certificate> x509CertChain = X509CertChainUtils.parse(header.getX509CertChain());
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certificateFactory.generateCertPath(x509CertChain);
            PKIXParameters pkixParameters = new PKIXParameters(trustStore);
            pkixParameters.setRevocationEnabled(false);
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            certPathValidator.validate(certPath, pkixParameters);
            X509Certificate signingCert = x509CertChain.getFirst();
            signingCert.checkValidity();
            String dSNName = X509CertUtil.getSubjectAlternativeNameDNSName(signingCert);
            if (!subjectAlternativeNameDNSName.equals(dSNName)) {
                throw new WalletException("Invalid SAN dNSName ");
            }
            return signingCert;
        } catch (Exception ex) {
            throw new KeySourceException("Invalid x5chain", ex);
        }
    }
}
