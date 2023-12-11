package ee.ria.eudi.qeaa.wallet.validation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.model.RequestObject;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class AuthorizationRequestValidator {
    public static final String JWT_TYPE_OAUTH_AUTHZ_REQ_JWT = "oauth-authz-req+jwt";
    private final SslBundles sslBundles;
    private final ObjectMapper objectMapper;
    private final Set<JWSAlgorithm> acceptedJWSAlgorithms = Set.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384,
        JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

    public RequestObject validate(SignedJWT requestObject, String clientId) {
        try {
            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(new X5ChainKeySelector(clientId, acceptedJWSAlgorithms, sslBundles.getBundle("eudi-wallet").getStores().getTrustStore()));
            jwtProcessor.setJWTClaimsSetVerifier(new AuthorizationRequestClaimsVerifier(clientId));
            jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(JWT_TYPE_OAUTH_AUTHZ_REQ_JWT)));
            jwtProcessor.process(requestObject, null);

            return objectMapper.readValue(requestObject.getPayload().toString(), RequestObject.class);
        } catch (BadJOSEException | JOSEException | JsonProcessingException ex) {
            throw new WalletException("Invalid request object", ex);
        }
    }
}
