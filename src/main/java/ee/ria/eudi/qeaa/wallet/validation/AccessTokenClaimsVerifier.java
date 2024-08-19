package ee.ria.eudi.qeaa.wallet.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import ee.ria.eudi.qeaa.wallet.error.WalletException;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AccessTokenClaimsVerifier<C extends SecurityContext> extends DefaultJWTClaimsVerifier<C> {
    private final String keyThumbprint;

    public AccessTokenClaimsVerifier(String issuer, String audience, String clientId, String keyThumbprint) {
        super(new JWTClaimsSet.Builder()
                .claim(JWTClaimNames.ISSUER, issuer)
                .claim(JWTClaimNames.AUDIENCE, List.of(audience))
                .claim("client_id", clientId)
                .build(),
            Set.of(JWTClaimNames.SUBJECT, JWTClaimNames.ISSUED_AT, JWTClaimNames.EXPIRATION_TIME, "cnf"));
        this.keyThumbprint = keyThumbprint;
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, C context) throws BadJWTException {
        super.verify(claimsSet, context);
        try {
            Map<String, Object> cnfClaim = claimsSet.getJSONObjectClaim("cnf");
            if (!keyThumbprint.equals(cnfClaim.get("jkt"))) {
                throw new WalletException("Invalid access token DPoP thumbprint");
            }
        } catch (ParseException e) {
            throw new WalletException("Invalid access token", e);
        }
    }
}
