package ee.ria.eudi.qeaa.wallet.service;

import com.nimbusds.jose.jwk.JWKSet;
import ee.ria.eudi.qeaa.wallet.configuration.properties.WalletProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_JSON;

@Slf4j
@Service
@RequiredArgsConstructor
public class MetadataService {
    public static final String OPENID_PROVIDER_WELL_KNOWN_PATH = "/.well-known/openid-configuration";
    public static final String CREDENTIAL_ISSUER_WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer";
    private final WalletProperties walletProperties;
    private final RestClient.Builder restClientBuilder;
    private final RestClientSsl ssl;
    private RestClient restClient;

    @PostConstruct
    private void setupRestClient() {
        restClient = restClientBuilder.apply(ssl.fromBundle("eudi-wallet")).build();
    }

    @Cacheable("issuer-metadata")
    public CredentialIssuerMetadata getCredentialIssuerMetadata() {
        return request(walletProperties.issuer().baseUrl() + CREDENTIAL_ISSUER_WELL_KNOWN_PATH, CredentialIssuerMetadata.class);
    }

    @Cacheable("as-metadata")
    public AuthorizationServerMetadata getAuthorizationServerMetadata() {
        CredentialIssuerMetadata credentialIssuerMetadata = getCredentialIssuerMetadata();
        List<String> authorizationServers = credentialIssuerMetadata.authorizationServers();
        if (authorizationServers != null && !authorizationServers.isEmpty()) {
            return request(authorizationServers.getFirst() + OPENID_PROVIDER_WELL_KNOWN_PATH, AuthorizationServerMetadata.class);
        } else {
            return request(credentialIssuerMetadata.credentialIssuer() + OPENID_PROVIDER_WELL_KNOWN_PATH, AuthorizationServerMetadata.class);
        }
    }

    @SneakyThrows
    @Cacheable("as-jwkset")
    public JWKSet getAuthorizationServerJWKSet() {
        AuthorizationServerMetadata metadata = getAuthorizationServerMetadata();
        return JWKSet.parse(request(metadata.jwksUri(), String.class));
    }

    private <T> T request(String uri, Class<T> clazz) {
        return restClient.get()
            .uri(uri)
            .accept(APPLICATION_JSON)
            .retrieve()
            .body(clazz);
    }
}
