#!/bin/sh
# Reference ASiC-S containers made by AutoFirma 1.9 (AOCAdESASiCSSigner and
# AOXAdESASiCSSigner, which the AutoFirma CLI does not expose), signing
# tests/data/xades/doc.txt. They change on every run, so they are not regenerated here:
#
#   J="java -cp /usr/lib/Autofirma/autofirma.jar ../../../tools/AfirmaAsic.java"
#   $J ../certs/rsa.p12 ../xades/doc.txt cades autofirma-cades-rsa.asics
#   $J ../certs/rsa.p12 ../xades/doc.txt xades autofirma-xades-rsa.asics
#
# Under the VS Code snap, run java with a clean environment (env -i PATH=/usr/bin:/bin java ...).
exit 0
