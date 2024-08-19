package ee.ria.eudi.qeaa.wallet.util;

import COSE.AlgorithmID;
import id.walt.mdoc.dataelement.ByteStringElement;
import id.walt.mdoc.dataelement.EncodedCBORElement;
import id.walt.mdoc.dataelement.ListElement;
import id.walt.mdoc.dataelement.MapElement;
import id.walt.mdoc.dataelement.NullElement;
import id.walt.mdoc.dataelement.StringElement;
import id.walt.mdoc.mdocauth.DeviceAuthentication;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Slf4j
@UtilityClass
public class MDocUtil {
    public static final String KEY_ID_DEVICE = "device-key-id";

    public DeviceAuthentication getDeviceAuthentication(String clientId, String doctype, String responseUri, String nonce, String mdocNonce) {
        ListElement sessionTranscript = new ListElement(
            List.of(
                new NullElement(),
                new NullElement(),
                getOID4VPHandover(clientId, responseUri, nonce, mdocNonce)));
        EncodedCBORElement deviceNameSpaces = new EncodedCBORElement(new MapElement(Map.of()));
        return new DeviceAuthentication(sessionTranscript, doctype, deviceNameSpaces);
    }

    @SneakyThrows
    private ListElement getOID4VPHandover(String clientId, String responseUri, String nonce, String mdocNonce) {
        log.debug("OID4VPHandover - client_id: {}, response_uri: {}, nonce: {}, mdoc_nonce: {}", clientId, responseUri, nonce, mdocNonce);
        byte[] clientIdToHash = new ListElement(List.of(new StringElement(clientId), new StringElement(mdocNonce))).toCBOR();
        byte[] responseUriToHash = new ListElement(List.of(new StringElement(responseUri), new StringElement(mdocNonce))).toCBOR();
        byte[] clientIdHash = MessageDigest.getInstance("SHA-256").digest(clientIdToHash);
        byte[] responseUriHash = MessageDigest.getInstance("SHA-256").digest(responseUriToHash);
        return new ListElement(List.of(new ByteStringElement(clientIdHash), new ByteStringElement(responseUriHash), new StringElement(nonce)));
    }

    public static String generateMdocNonce() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public AlgorithmID getAlgorithmId(PublicKey publicKey) {
        if (publicKey instanceof ECPublicKey ecPublicKey) {
            int bitLength = ecPublicKey.getParams().getOrder().bitLength();
            return switch (bitLength) {
                case 256 -> AlgorithmID.ECDSA_256;
                case 384 -> AlgorithmID.ECDSA_384;
                case 521 -> AlgorithmID.ECDSA_512;
                default -> throw new IllegalArgumentException("Unsupported key size: " + bitLength);
            };
        } else {
            throw new IllegalArgumentException("Invalid key type. An Elliptic Curve key is required by ISO/IEC 18013-5:2021.");
        }
    }
}
