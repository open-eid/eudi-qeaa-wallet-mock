package ee.ria.eudi.qeaa.wallet.service;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import static org.springframework.http.MediaType.APPLICATION_JSON;

@Service
@RequiredArgsConstructor
public class RelyingPartyService {
    public static final MediaType MEDIA_TYPE_APPLICATION_OAUTH_AUTHZ_REQ_JWT = new MediaType("application", "oauth-authz-req+jwt");
    private final RestClient.Builder restClientBuilder;
    private final RestClientSsl ssl;
    private RestClient restClient;

    @PostConstruct
    private void setupRestClient() {
        restClient = restClientBuilder.apply(ssl.fromBundle("eudi-wallet")).build();
    }

    @SneakyThrows
    public SignedJWT getRequestObject(String requestUri) {
        String jwt = restClient.get()
            .uri(requestUri)
            .accept(MEDIA_TYPE_APPLICATION_OAUTH_AUTHZ_REQ_JWT)
            .retrieve()
            .body(String.class);
        return jwt == null ? null : SignedJWT.parse(jwt);
    }

    public ResponseObjectResponse postResponseObject(String responseObjectEndpoint, EncryptedJWT response, String state) {
        LinkedMultiValueMap<String, Object> payload = new LinkedMultiValueMap<>();
        payload.add("response", response.serialize());
        payload.add("state", state);
        return postResponseObject(responseObjectEndpoint, payload);
    }

    public ResponseObjectResponse postErrorResponse(String responseObjectEndpoint, String error, String errorDescription) {
        LinkedMultiValueMap<String, Object> payload = new LinkedMultiValueMap<>();
        payload.add("error", error);
        payload.add("error_description", errorDescription);
        return postResponseObject(responseObjectEndpoint, payload);
    }

    private ResponseObjectResponse postResponseObject(String responseObjectEndpoint, LinkedMultiValueMap<String, Object> payload) {
        return restClient.post()
            .uri(responseObjectEndpoint)
            .body(payload)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(APPLICATION_JSON)
            .retrieve()
            .body(ResponseObjectResponse.class);
    }
}
