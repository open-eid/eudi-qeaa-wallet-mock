package ee.ria.eudi.qeaa.wallet.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.persistence.Embeddable;
import lombok.Data;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.net.URL;
import java.util.Map;

@Embeddable
@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public final class VerifierMetadata {
    private String clientName;
    private String clientUri;
    private String logoUri;
    private String authorizationEncryptedResponseAlg;
    private String authorizationEncryptedResponseEnc;
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> jwks;
    private URL jwksUri;
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> vpFormats;

}
