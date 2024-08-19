package ee.ria.eudi.qeaa.wallet.model;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Entity
@Table(name = "request_objects")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public final class RequestObject {
    @Id
    private String state;
    private String nonce;
    private String clientId;
    private ClientIdScheme clientIdScheme;
    private ResponseType responseType;
    private ResponseMode responseMode;
    private String responseUri;
    @Embedded
    private VerifierMetadata clientMetadata;
    @OneToOne(cascade = CascadeType.ALL)
    private PresentationDefinition presentationDefinition;

    public enum ClientIdScheme {
        X509_SAN_DNS, VERIFIER_ATTESTATION;

        @JsonValue
        public String value() {
            return this.name().toLowerCase();
        }
    }

    @RequiredArgsConstructor
    public enum ResponseType {
        VP_TOKEN("vp_token"), VP_TOKEN_ID_TOKEN("vp_token id_token"), CODE("code");
        private final String value;

        @JsonValue
        public String value() {
            return value;
        }
    }

    @RequiredArgsConstructor
    public enum ResponseMode {
        DIRECT_POST("direct_post"), DIRECT_POST_JWT("direct_post.jwt");
        private final String value;

        @JsonValue
        public String value() {
            return value;
        }
    }
}
