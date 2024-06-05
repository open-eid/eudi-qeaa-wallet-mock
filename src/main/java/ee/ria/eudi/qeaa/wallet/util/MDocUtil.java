package ee.ria.eudi.qeaa.wallet.util;

import COSE.AlgorithmID;
import id.walt.mdoc.dataelement.DataElement;
import id.walt.mdoc.dataelement.EncodedCBORElement;
import id.walt.mdoc.dataelement.ListElement;
import id.walt.mdoc.dataelement.MapElement;
import id.walt.mdoc.dataelement.NullElement;
import id.walt.mdoc.dataelement.StringElement;
import id.walt.mdoc.mdocauth.DeviceAuthentication;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;

@Slf4j
@UtilityClass
public class MDocUtil {
    public static final String KEY_ID_DEVICE = "device-key-id";

    public DeviceAuthentication getDeviceAuthentication(String clientId, String doctype, String nonce) {
        ListElement sessionTranscript = new ListElement(
            List.<DataElement<?>>of(
                new NullElement(),
                new NullElement(),
                new ListElement(
                    List.of(
                        new StringElement("openID4VPHandover"),
                        new StringElement(clientId),
                        new StringElement(nonce))
                )

            )
        );
        EncodedCBORElement deviceNameSpaces = new EncodedCBORElement(new MapElement(Map.of()));
        return new DeviceAuthentication(sessionTranscript, doctype, deviceNameSpaces);
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
