package ee.ria.eudi.qeaa.wallet.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.persistence.CascadeType;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Entity
@Table(name = "presentation_definitions")
@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public final class PresentationDefinition {
    @Id
    private String id;
    private String name;
    private String purpose;
    @OneToMany(cascade = CascadeType.ALL)
    private List<InputDescriptor> inputDescriptors;

    @Entity
    @Table(name = "input_descriptors")
    @Data
    @NoArgsConstructor
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static final class InputDescriptor {
        @Id
        private String id;
        @Transient
        private Map<String, Object> format;
        @Embedded
        private Constraints constraints;

    }

    @Embeddable
    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static final class Constraints {
        private String limitDisclosure;
        @ElementCollection
        private List<Field> fields;

    }

    @Embeddable
    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static final class Field {
        private List<String> path;
        private Filter filter;
        private boolean intentToRetain;
    }

    @Embeddable
    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static final class Filter {
        private String type;
        private String pattern;
    }
}
