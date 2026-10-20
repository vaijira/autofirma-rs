// Signs, co-signs and counter-signs with AutoFirma's own signers, to make
// reference files (tests/data) and to check that AutoFirma can add signatures
// to ours.
//
// Usage:
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaMulti.java KEYSTORE.p12 OPERATION FORMAT IN OUT [DATA]
//
// OPERATION: sign | cosign | countersign-tree | countersign-leafs
// FORMAT:    cades | xades | odf | ooxml
// DATA:      the signed data, to co-sign explicit CAdES signatures.
//
// The keystore password is 1234, as for every test keystore. The signature
// algorithm is SHA512with{RSA,ECDSA}; AutoFirma's ODF signer always uses RSA-SHA1.

import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.odf.AOODFSigner;
import es.gob.afirma.signers.ooxml.AOOOXMLSigner;
import es.gob.afirma.signers.xades.AOXAdESSigner;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Properties;

public class AfirmaMulti {
    public static void main(String[] a) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(a[0]), "1234".toCharArray());
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, "1234".toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        String algorithm = "SHA512with" + (pk.getAlgorithm().equals("EC") ? "ECDSA" : "RSA");

        AOSigner signer = switch (a[2]) {
            case "cades" -> new AOCAdESSigner();
            case "xades" -> new AOXAdESSigner();
            case "odf" -> new AOODFSigner();
            case "ooxml" -> new AOOOXMLSigner();
            default -> throw new IllegalArgumentException("formato " + a[2]);
        };
        byte[] in = Files.readAllBytes(Path.of(a[3]));
        Properties params = new Properties();
        byte[] out = switch (a[1]) {
            case "sign" -> signer.sign(in, algorithm, pk, chain, params);
            case "cosign" -> a.length > 5
                ? signer.cosign(Files.readAllBytes(Path.of(a[5])), in, algorithm, pk, chain, params)
                : signer.cosign(in, algorithm, pk, chain, params);
            case "countersign-tree" -> signer.countersign(in, algorithm, CounterSignTarget.TREE, null, pk, chain, params);
            case "countersign-leafs" -> signer.countersign(in, algorithm, CounterSignTarget.LEAFS, null, pk, chain, params);
            default -> throw new IllegalArgumentException("operación " + a[1]);
        };
        Files.write(Path.of(a[4]), out);
    }
}
