package ee.ria.eudi.qeaa.wallet.configuration.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "eudi")
public record WalletProperties(
    @NotNull
    Wallet wallet,
    @NotNull
    CredentialIssuer issuer) {

    @ConfigurationProperties(prefix = "eudi.wallet")
    public record Wallet(
        @NotBlank
        String baseUrl,
        @NotNull
        TimeToLive ttl) {
    }

    @ConfigurationProperties(prefix = "eudi.issuer")
    public record CredentialIssuer(
        @NotBlank
        String baseUrl) {

    }

    @ConfigurationProperties(prefix = "eudi.wallet.ttl")
    public record TimeToLive(
        @NotNull
        Duration parRequestObject) {

    }
}
