package ee.ria.eudi.qeaa.wallet.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;

import java.time.LocalDateTime;

@Entity
@Table(name = "credentials")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Credential {
    public static final String CREDENTIAL_FORMAT_MSO_MDOC = "mso_mdoc";
    private static final ObjectMapper mapper = new ObjectMapper();

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Lob
    @Column(name = "credential_value")
    private String value;
    private String format;
    private String doctype;
    private LocalDateTime issuedAt;
    @Lob
    private String accessToken;
    private String cNonce;
    private Long cNonceExpiresIn;

    @SneakyThrows
    public String formattedAccessToken() {
        if (accessToken == null) {
            return null;
        }
        SignedJWT signedJWT = SignedJWT.parse(accessToken);
        Object jsonObject = mapper.readValue(signedJWT.getPayload().toString(), Object.class);
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
    }
}
