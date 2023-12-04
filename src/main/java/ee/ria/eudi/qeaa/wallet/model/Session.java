package ee.ria.eudi.qeaa.wallet.model;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.text.ParseException;

@Entity
@Table(name = "sessions")
@Data
@NoArgsConstructor
public class Session {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String state;
    private CodeVerifier codeVerifier;

    @Builder
    public Session(JWTClaimsSet requestObjectClaims, CodeVerifier codeVerifier) throws ParseException {
        state = requestObjectClaims.getStringClaim("state");
        this.codeVerifier = codeVerifier;
    }
}
