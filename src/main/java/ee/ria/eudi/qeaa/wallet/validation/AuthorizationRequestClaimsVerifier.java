package ee.ria.eudi.qeaa.wallet.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import ee.ria.eudi.qeaa.wallet.error.WalletException;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

import static ee.ria.eudi.qeaa.wallet.model.RequestObject.ClientIdScheme.X509_SAN_DNS;
import static ee.ria.eudi.qeaa.wallet.model.RequestObject.ResponseMode.DIRECT_POST_JWT;
import static ee.ria.eudi.qeaa.wallet.model.RequestObject.ResponseType.VP_TOKEN;

public class AuthorizationRequestClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {

    public AuthorizationRequestClaimsVerifier(String clientId) {
        super(new JWTClaimsSet.Builder()
                .claim("response_type", VP_TOKEN.value())
                .claim("response_mode", DIRECT_POST_JWT.value())
                .claim("client_id", clientId)
                .claim("client_id_scheme", X509_SAN_DNS.value())
                .build(),
            Set.of("response_uri", "client_metadata", "presentation_definition", "nonce", "state", "client_id_scheme"));
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);
        if (claimsSet.getClaim("redirect_uri") != null) {
            throw new WalletException("Redirect uri not supported. Use direct_post response mode.");
        }
        try {
            Map<String, Object> clientMetadata = claimsSet.getJSONObjectClaim("client_metadata");
            if (!clientMetadata.containsKey("authorization_encrypted_response_alg")) {
                throw new WalletException("JWT missing required claims: authorization_encrypted_response_alg");
            }
            if (!clientMetadata.containsKey("authorization_encrypted_response_enc")) {
                throw new WalletException("JWT missing required claims: authorization_encrypted_response_enc");
            }
            if (!clientMetadata.containsKey("jwks") && !clientMetadata.containsKey("jwks_uri")) {
                throw new WalletException("JWT missing required claims: jwks or jwks_uri");
            }
        } catch (ParseException e) {
            throw new WalletException("Invalid verifier metadata", e);
        }
    }
}
