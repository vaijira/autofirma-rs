#!/bin/sh
# Regenerates the test PDFs. Needs mutool (MuPDF) and qpdf.
#
# - doc.pdf:        one A4 page, classic xref table
# - doc-xref.pdf:   two pages (A4 and landscape A4), object and xref streams (PDF 1.5)
# - doc-aes256.pdf: doc.pdf encrypted with AES-256 (user password "user", owner "owner")
# - doc-rc4.pdf:    doc.pdf encrypted with RC4-128 (user password empty, owner "owner")
set -eu
cd "$(dirname "$0")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

page() { # file width height text
  cat > "$1" <<EOF
%%MediaBox 0 0 $2 $3
%%Font Helv Helvetica
BT
/Helv 24 Tf
72 $(($3 - 100)) Td
($4) Tj
0 -36 Td
/Helv 12 Tf
(Documento de prueba de autofirma-rs.) Tj
ET
EOF
}

page "$TMP/p1.txt" 595 842 "Pagina 1"
page "$TMP/p2.txt" 842 595 "Pagina 2 (apaisada)"

mutool create -o "$TMP/doc.pdf" "$TMP/p1.txt"
mutool create -o "$TMP/doc2.pdf" "$TMP/p1.txt" "$TMP/p2.txt"

# Deterministic output: fixed /ID and no generator-specific metadata changes.
qpdf --static-id --object-streams=disable --compress-streams=n "$TMP/doc.pdf" doc.pdf
qpdf --static-id --object-streams=generate "$TMP/doc2.pdf" doc-xref.pdf
qpdf --static-id --encrypt user owner 256 -- doc.pdf doc-aes256.pdf
qpdf --static-id --allow-weak-crypto --encrypt "" owner 128 --use-aes=n -- doc.pdf doc-rc4.pdf

# Reference signatures made by AutoFirma 1.9 (autofirma-*.pdf) are not regenerated here,
# since they change on every run. They were made with:
#
#   AF="java -Djava.awt.headless=true -jar /usr/lib/Autofirma/autofirma.jar sign -format pades"
#   KEY="-store pkcs12:../certs/rsa.p12 -password 1234 -alias rsa"
#   $AF -i doc.pdf -o autofirma-bes-rsa.pdf $KEY
#   $AF -i doc.pdf -o autofirma-age-rsa.pdf $KEY -config 'policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9\npolicyIdentifierHash=G7roucf600+f03r/o0bAOQ6WAs0=\npolicyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1\npolicyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf\nsignReason=Prueba\nsignatureProductionCity=Madrid'
#   $AF -i doc.pdf -o autofirma-visible-rsa.pdf $KEY -config 'signaturePage=1\nsignaturePositionOnPageLowerLeftX=72\nsignaturePositionOnPageLowerLeftY=72\nsignaturePositionOnPageUpperRightX=272\nsignaturePositionOnPageUpperRightY=142\nlayer2Text=Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$\ncertificationLevel=1'
#   $AF -i doc-aes256.pdf -o autofirma-aes256-rsa.pdf $KEY -config 'ownerPassword=owner\nuserPassword=user'
#   $AF -i autofirma-bes-rsa.pdf -o autofirma-cosign-ec.pdf -store pkcs12:../certs/ec.p12 -password 1234 -alias ec
#
# -config takes literal \n separators. Under the VS Code snap, run java with a clean
# environment (env -i PATH=/usr/bin:/bin java ...).
