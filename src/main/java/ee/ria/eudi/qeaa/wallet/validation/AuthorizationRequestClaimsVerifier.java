package ee.ria.eudi.qeaa.wallet.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import ee.ria.eudi.qeaa.wallet.error.WalletException;

import java.util.Set;

import static ee.ria.eudi.qeaa.wallet.model.RequestObject.ClientIdScheme.X509_SAN_DNS;
import static ee.ria.eudi.qeaa.wallet.model.RequestObject.ResponseMode.DIRECT_POST;
import static ee.ria.eudi.qeaa.wallet.model.RequestObject.ResponseType.VP_TOKEN;

public class AuthorizationRequestClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {

    public AuthorizationRequestClaimsVerifier(String clientId) {
        super(new JWTClaimsSet.Builder()
                .claim("response_type", VP_TOKEN.value())
                .claim("response_mode", DIRECT_POST.value())
                .claim("client_id", clientId)
                .claim("client_id_scheme", X509_SAN_DNS.value())
                .build(),
            Set.of("response_uri", "client_metadata", "presentation_definition", "nonce", "state"));
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);
        if (claimsSet.getClaim("redirect_uri") != null) {
            throw new WalletException("Only direct_post is supported");
        }
    }
}
