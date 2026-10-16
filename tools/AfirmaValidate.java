// Validates a CAdES/CMS or PAdES signature with AutoFirma's own validators, to
// cross-check signatures produced by autofirma-rs.
//
// Usage:
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java SIGNATURE [DATA]
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java SIGNED.pdf [PASSWORD]
//
// DATA is required for explicit (detached) CAdES signatures. PASSWORD opens
// encrypted PDFs. Exits with 0 when every result is OK. Certificate trust (our
// test CA) is not checked by AutoFirma here.

import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.ValidateBinarySignature;
import es.gob.afirma.signvalidation.ValidatePdfSignature;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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
            ok &= result.getValidity() == SignValidity.SIGN_DETAIL_TYPE.OK;
        }
        System.exit(ok ? 0 : 1);
    }
}
