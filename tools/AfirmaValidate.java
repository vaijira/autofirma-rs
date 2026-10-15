// Validates a CAdES/CMS signature with AutoFirma's own validator, to cross-check
// signatures produced by autofirma-rs.
//
// Usage:
//   java -cp /usr/lib/Autofirma/autofirma.jar tools/AfirmaValidate.java SIGNATURE [DATA]
//
// DATA is required for explicit (detached) signatures. Exits with 0 when every
// result is OK. Certificate trust (our test CA) is not checked by AutoFirma here.

import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.ValidateBinarySignature;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class AfirmaValidate {
    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) {
            System.err.println("Usage: AfirmaValidate SIGNATURE [DATA]");
            System.exit(2);
        }
        byte[] sign = Files.readAllBytes(Path.of(args[0]));
        byte[] data = args.length == 2 ? Files.readAllBytes(Path.of(args[1])) : null;

        List<SignValidity> results = ValidateBinarySignature.validate(sign, data);
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
