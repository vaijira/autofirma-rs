// Minimal triphase signature server for interoperability tests.
//
// Speaks the same protocol as clienteafirma's `afirma-server-triphase-signer`
// (SignatureService) and delegates the signature work to that project's own
// pre/post processors, compiled from source by run.sh against autofirma.jar.
// The document manager is the "selfish" one: `doc` is the document in Base64 and
// the post response returns the signed document as `OK NEWID=<Base64>`.
//
// For tests only: no HMAC session protection, no cache, CORS open to any origin.

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.ExtraParamsProcessor;
import es.gob.afirma.core.signers.TriphaseData;
import es.gob.afirma.triphase.signer.processors.CAdESTriPhasePreProcessor;
import es.gob.afirma.triphase.signer.processors.PAdESTriPhasePreProcessor;
import es.gob.afirma.triphase.signer.processors.TriPhasePreProcessor;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class TriphaseServer {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8090;
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/afirma-server-triphase-signer/SignatureService", TriphaseServer::handle);
        server.start();
        System.out.println("Triphase server on http://127.0.0.1:" + port + "/afirma-server-triphase-signer/SignatureService");
    }

    private static void handle(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }
        String response;
        try {
            response = process(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            response = "ERR-99:" + e;
        }
        byte[] body = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static String process(String body) throws Exception {
        Map<String, String> params = new HashMap<>();
        for (String param : body.split("&")) {
            int eq = param.indexOf('=');
            if (eq != -1) {
                params.put(param.substring(0, eq), URLDecoder.decode(param.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        String op = params.get("op");
        String cop = params.get("cop");
        String format = params.get("format");
        if (!"sign".equals(cop)) {
            return "ERR-04:Solo se admite cop=sign";
        }

        Properties extraParams = params.containsKey("params")
            ? AOUtil.base642Properties(params.get("params"))
            : new Properties();
        extraParams.setProperty("headless", "true");
        extraParams = ExtraParamsProcessor.expandProperties(extraParams, null, format);

        String[] certs = params.get("cert").split(",");
        X509Certificate[] chain = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            chain[i] = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.decode(certs[i], true)));
        }
        byte[] document = Base64.decode(params.get("doc"), true);

        TriPhasePreProcessor processor;
        if ("pades".equalsIgnoreCase(format)) {
            processor = new PAdESTriPhasePreProcessor();
        } else if ("cades".equalsIgnoreCase(format)) {
            processor = new CAdESTriPhasePreProcessor();
        } else {
            return "ERR-06:Formato no soportado: " + format;
        }
        String algorithm = AOSignConstants.composeSignatureAlgorithmName(
            params.get("algo"), chain[0].getPublicKey().getAlgorithm());

        if ("pre".equals(op)) {
            TriphaseData pre = processor.preProcessPreSign(document, algorithm, chain, extraParams, false);
            return Base64.encode(pre.toString().getBytes(StandardCharsets.UTF_8), true);
        }
        if ("post".equals(op)) {
            TriphaseData session = TriphaseData.parser(Base64.decode(params.get("session").trim(), true));
            byte[] signed = processor.preProcessPostSign(document, algorithm, chain, extraParams, session);
            return "OK NEWID=" + Base64.encode(signed, true);
        }
        return "ERR-01:Operacion no soportada: " + op;
    }
}
