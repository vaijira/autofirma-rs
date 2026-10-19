// Signs a file in an ASiC-S container with AutoFirma's own signers, to make
// reference containers (tests/data/asic).
//
// Usage:
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaAsic.java KEYSTORE.p12 DATA cades|xades OUT [FILE_NAME]
//
// The keystore password is 1234, as for every test keystore.

import es.gob.afirma.signers.cades.asic.AOCAdESASiCSSigner;
import es.gob.afirma.signers.xades.asic.AOXAdESASiCSSigner;
import java.io.FileInputStream;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Properties;
public class AfirmaAsic { public static void main(String[] a) throws Exception {
  KeyStore ks = KeyStore.getInstance("PKCS12"); ks.load(new FileInputStream(a[0]), "1234".toCharArray());
  String alias = ks.aliases().nextElement();
  PrivateKey pk = (PrivateKey) ks.getKey(alias, "1234".toCharArray());
  Certificate[] chain = ks.getCertificateChain(alias);
  byte[] data = Files.readAllBytes(Path.of(a[1]));
  Properties p = new Properties();
  if (a.length > 4) p.setProperty("asicsFilename", a[4]);
  byte[] out = a[2].equals("cades") ? new AOCAdESASiCSSigner().sign(data, "SHA512withRSA", pk, chain, p)
                                    : new AOXAdESASiCSSigner().sign(data, "SHA512withRSA", pk, chain, p);
  Files.write(Path.of(a[3]), out); } }
