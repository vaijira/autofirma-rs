// Validates a CAdES/CMS, PAdES or XAdES signature with AutoFirma's own
// validators, to cross-check signatures produced by autofirma-rs.
//
// Usage:
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java SIGNATURE [DATA]
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java SIGNED.pdf [PASSWORD]
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java SIGNATURE.xsig
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java CONTAINER.asics
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java SIGNED.odt|SIGNED.docx
//
// DATA is required for explicit (detached) CAdES signatures. PASSWORD opens
// encrypted PDFs. AutoFirma has no validator for ODF and OOXML documents nor
// for XAdES-ASiC-S: they are checked with the JDK's XMLDSig, with AutoFirma's
// OPC relationship transform for OOXML (manifest references included). Exits with 0 when every result is OK, or when AutoFirma only
// reports that it did not check the profile of a timestamped signature.
// Certificate trust (our test CA) is not checked by AutoFirma here.

import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.ValidateBinarySignature;
import es.gob.afirma.signvalidation.ValidatePdfSignature;
import es.gob.afirma.signvalidation.ValidateXMLSignature;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.Properties;

public class AfirmaValidate {
    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) {
            System.err.println("Usage: AfirmaValidate SIGNATURE [DATA | PDF_PASSWORD]");
            System.exit(2);
        }
        byte[] sign = Files.readAllBytes(Path.of(args[0]));

        List<SignValidity> results;
        if (new String(sign, 0, Math.min(5, sign.length), "ISO-8859-1").equals("%PDF-")) {
            Properties params = new Properties();
            if (args.length == 2) {
                params.setProperty("ownerPassword", args[1]);
                params.setProperty("userPassword", args[1]);
            }
            results = new ValidatePdfSignature().validate(sign, params);
        } else if (sign.length > 4 && sign[0] == 'P' && sign[1] == 'K') {
            // ASiC-S: the signature over the one data file.
            Map<String, byte[]> entries = new HashMap<>();
            byte[] data = null;
            try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(sign))) {
                for (ZipEntry entry; (entry = zip.getNextEntry()) != null; ) {
                    byte[] content = zip.readAllBytes();
                    entries.put(entry.getName(), content);
                    if (!entry.getName().equals("mimetype") && !entry.getName().startsWith("META-INF/")) {
                        data = content;
                    }
                }
            }
            if (entries.containsKey("META-INF/documentsignatures.xml")) {
                boolean valid = validatePackage(entries.get("META-INF/documentsignatures.xml"), entries, false);
                System.out.println("JDK XMLDSig (ODF): " + (valid ? "OK" : "KO"));
                System.exit(valid ? 0 : 1);
                return;
            }
            if (entries.keySet().stream().anyMatch(n -> n.startsWith("_xmlsignatures/") && n.endsWith(".xml"))) {
                java.security.Security.addProvider(new es.gob.afirma.signers.ooxml.relprovider.OOXMLProvider());
                boolean valid = true;
                for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                    String name = entry.getKey();
                    if (name.startsWith("_xmlsignatures/") && name.endsWith(".xml")) {
                        boolean ok = validatePackage(entry.getValue(), entries, true);
                        System.out.println("JDK XMLDSig (OOXML " + name + "): " + (ok ? "OK" : "KO"));
                        valid &= ok;
                    }
                }
                System.exit(valid ? 0 : 1);
                return;
            }
            if (entries.containsKey("META-INF/signature.p7s")) {
                results = ValidateBinarySignature.validate(entries.get("META-INF/signature.p7s"), data);
            } else {
                // AutoFirma's XML validator cannot dereference the data file (not
                // even in its own containers): check with the JDK's XMLDSig instead.
                boolean valid = validateDetachedXml(entries.get("META-INF/signatures.xml"), data);
                System.out.println("JDK XMLDSig: " + (valid ? "OK" : "KO"));
                System.exit(valid ? 0 : 1);
                return;
            }
        } else if (isXml(sign)) {
            results = new ValidateXMLSignature().validate(sign, false);
        } else {
            byte[] data = args.length == 2 ? Files.readAllBytes(Path.of(args[1])) : null;
            results = ValidateBinarySignature.validate(sign, data);
        }

        boolean ok = !results.isEmpty();
        for (SignValidity result : results) {
            System.out.println(result.getValidity() + (result.getError() != null ? " " + result.getError() : ""));
            if (result.getErrorException() != null) {
                System.out.println("  " + result.getErrorException());
            }
            // Timestamped (T-level) signatures: AutoFirma checks only their B-level part.
            boolean profileNotChecked = result.getValidity() == SignValidity.SIGN_DETAIL_TYPE.UNKNOWN
                && result.getError() == SignValidity.VALIDITY_ERROR.SIGN_PROFILE_NOT_CHECKED;
            ok &= result.getValidity() == SignValidity.SIGN_DETAIL_TYPE.OK || profileNotChecked;
        }
        System.exit(ok ? 0 : 1);
    }

    /** First character after an optional UTF-8 byte order mark and whitespace is '<'. */
    private static boolean isXml(byte[] data) {
        int i = data.length >= 3 && (data[0] & 0xff) == 0xef ? 3 : 0;
        while (i < data.length && Character.isWhitespace(data[i])) {
            i++;
        }
        return i < data.length && data[i] == '<';
    }

    /**
     * Validates every XML signature of a signature part of an ODF or OOXML
     * package, resolving package-relative URIs to its entries. With
     * `manifests`, the references of the ds:Manifests are checked too.
     */
    private static boolean validatePackage(byte[] xml, Map<String, byte[]> entries, boolean manifests) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element element = (Element) all.item(i);
            if (element.hasAttribute("Id")) {
                element.setIdAttribute("Id", true);
            }
        }
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        NodeList signatures = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        boolean valid = signatures.getLength() > 0;
        for (int i = 0; i < signatures.getLength(); i++) {
            Element signature = (Element) signatures.item(i);
            String certificate = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate").item(0)
                .getTextContent().replaceAll("\\s", "");
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(certificate)));
            DOMValidateContext context = new DOMValidateContext(cert.getPublicKey(), signature);
            // AutoFirma's own ODF signatures use RSA-SHA1, which secure validation forbids.
            context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
            context.setURIDereferencer((reference, ctx) -> {
                String uri = reference.getURI();
                if (uri.startsWith("#")) {
                    return factory.getURIDereferencer().dereference(reference, ctx);
                }
                String name = java.net.URLDecoder.decode(uri.replaceFirst("^/", "").replaceFirst("\\?.*$", "")
                    .replace("+", "%2B"), java.nio.charset.StandardCharsets.UTF_8);
                byte[] part = entries.get(name);
                if (part == null) {
                    throw new javax.xml.crypto.URIReferenceException("no existe " + name);
                }
                return new OctetStreamData(new ByteArrayInputStream(part), uri, null);
            });
            XMLSignature xmlSignature = factory.unmarshalXMLSignature(context);
            boolean ok = xmlSignature.validate(context);
            if (!ok) {
                for (Object reference : xmlSignature.getSignedInfo().getReferences()) {
                    Reference r = (Reference) reference;
                    System.out.println("  " + r.getURI() + ": " + r.validate(context));
                }
            }
            if (manifests) {
                for (Object object : xmlSignature.getObjects()) {
                    for (Object content : ((XMLObject) object).getContent()) {
                        if (content instanceof Manifest manifest) {
                            for (Object reference : manifest.getReferences()) {
                                Reference r = (Reference) reference;
                                boolean refOk = r.validate(context);
                                if (!refOk) {
                                    System.out.println("  manifest " + r.getURI() + ": KO");
                                }
                                ok &= refOk;
                            }
                        }
                    }
                }
            }
            valid &= ok;
        }
        return valid;
    }

    /** Validates the first XML signature, giving `data` for references outside the document. */
    private static boolean validateDetachedXml(byte[] xml, byte[] data) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element element = (Element) all.item(i);
            if (element.hasAttribute("Id")) {
                element.setIdAttribute("Id", true);
            }
        }
        Element signature = (Element) doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
        String certificate = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate").item(0)
            .getTextContent().replaceAll("\\s", "");
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(certificate)));
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        DOMValidateContext context = new DOMValidateContext(cert.getPublicKey(), signature);
        context.setURIDereferencer((reference, ctx) -> reference.getURI().startsWith("#")
            ? factory.getURIDereferencer().dereference(reference, ctx)
            : new OctetStreamData(new ByteArrayInputStream(data)));
        return factory.unmarshalXMLSignature(context).validate(context);
    }
}
