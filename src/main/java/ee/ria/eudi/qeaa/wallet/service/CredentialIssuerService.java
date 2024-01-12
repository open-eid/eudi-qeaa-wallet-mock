package ee.ria.eudi.qeaa.wallet.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.factory.CredentialJwtKeyProofFactory;
import ee.ria.eudi.qeaa.wallet.model.CredentialErrorResponse;
import ee.ria.eudi.qeaa.wallet.model.CredentialRequest;
import ee.ria.eudi.qeaa.wallet.model.CredentialResponse;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.text.ParseException;

import static ee.ria.eudi.qeaa.wallet.model.Credential.CREDENTIAL_FORMAT_MSO_MDOC;
import static org.springframework.http.MediaType.APPLICATION_JSON;

@Service
@RequiredArgsConstructor
public class CredentialIssuerService {
    private final CredentialJwtKeyProofFactory credentialJwtKeyProofFactory;
    private final MetadataService metadataService;
    private final RestClient.Builder restClientBuilder;
    private final RestClientSsl ssl;
    private RestClient restClient;

    @PostConstruct
    private void setupRestClient() {
        restClient = restClientBuilder.apply(ssl.fromBundle("eudi-wallet")).build();
    }

    public CredentialResponse credentialRequest(SignedJWT accessToken, SignedJWT dPoPProof, SignedJWT credentialJwtKeyProof) {
        try {
            return request(accessToken, dPoPProof, credentialJwtKeyProof);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                CredentialErrorResponse errorResponse = e.getResponseBodyAs(CredentialErrorResponse.class);
                if (errorResponse != null && errorResponse.cNonce() != null) {
                    return retryRequestWithFreshNonce(accessToken, dPoPProof, errorResponse.cNonce());
                }
            }
            throw e;
        }
    }

    private CredentialResponse retryRequestWithFreshNonce(SignedJWT accessToken, SignedJWT dPoPProof, String freshNonce) {
        try {
            SignedJWT credentialJwtKeyProof = credentialJwtKeyProofFactory.create(freshNonce);
            return request(accessToken, dPoPProof, credentialJwtKeyProof);
        } catch (ParseException | JOSEException e) {
            throw new WalletException("Unable to request credential issuance", e);
        }
    }

    private CredentialResponse request(SignedJWT accessToken, SignedJWT dPoPProof, SignedJWT credentialJwtKeyProof) {
        return restClient.post()
            .uri(metadataService.getCredentialIssuerMetadata().credentialEndpoint())
            .header("Authorization", "DPoP " + accessToken.serialize())
            .header("DPoP", dPoPProof.serialize())
            .body(getRequestBody(credentialJwtKeyProof))
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .retrieve()
            .body(CredentialResponse.class);
    }

    private CredentialRequest getRequestBody(SignedJWT credentialJwtKeyProof) {
        CredentialRequest.Proof proof = CredentialRequest.Proof.builder()
            .proofType("jwt")
            .jwt(credentialJwtKeyProof.serialize())
            .build();
        return CredentialRequest.builder()
            .format(CREDENTIAL_FORMAT_MSO_MDOC)
            .doctype("org.iso.18013.5.1.mDL")
            .proof(proof)
            .build();
    }
}
