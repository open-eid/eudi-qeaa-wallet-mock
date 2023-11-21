package ee.ria.eudi.qeaa.wallet.model;

import com.nimbusds.jwt.JWTClaimsSet;
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
    private String codeChallenge;
    private String codeChallengeMethod;

    @Builder
    public Session(JWTClaimsSet requestObjectClaims) throws ParseException {
        state = requestObjectClaims.getStringClaim("state");
        codeChallenge = requestObjectClaims.getStringClaim("code_challenge");
        codeChallengeMethod = requestObjectClaims.getStringClaim("code_challenge_method");
    }
}

