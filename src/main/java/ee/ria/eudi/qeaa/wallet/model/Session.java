package ee.ria.eudi.qeaa.wallet.model;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "sessions")
@Data
@NoArgsConstructor
public class Session {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String state;
    private String redirectUri;
    private CodeVerifier codeVerifier;
    @OneToMany(cascade = CascadeType.ALL)
    private List<AuthorizationDetails> authorizationDetails;

    @Builder
    @SuppressWarnings("unchecked")
    public Session(JWTClaimsSet requestObjectClaims, CodeVerifier codeVerifier) throws ParseException {
        state = requestObjectClaims.getStringClaim("state");
        redirectUri = requestObjectClaims.getStringClaim("redirect_uri");
        this.codeVerifier = codeVerifier;
        authorizationDetails = requestObjectClaims.getListClaim("authorization_details").stream()
            .map(ad -> (Map<String, Object>) ad)
            .map(ad -> AuthorizationDetails.builder()
                .type((String) ad.get("type"))
                .format((String) ad.get("format"))
                .doctype((String) ad.get("doctype"))
                .locations((List<String>) ad.get("locations"))
                .build()
            ).toList();
    }
}
