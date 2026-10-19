#!/bin/sh
# Builds and runs tools/triphase-server/TriphaseServer.java, a test server with
# the pre/post processors of clienteafirma's afirma-server-triphase-signer.
#
# Needs a JDK (javac) and AutoFirma. The processors are downloaded once from
# clienteafirma at a pinned commit (v1.9, matching autofirma.jar 1.9) into target/triphase-server.
#
# Usage: tools/triphase-server/run.sh [PORT]     (default 8090)
# Env:   AUTOFIRMA_JAR (default /usr/lib/Autofirma/autofirma.jar)
set -eu
cd "$(dirname "$0")/../.."

PORT=${1:-8090}
JAR=${AUTOFIRMA_JAR:-/usr/lib/Autofirma/autofirma.jar}
COMMIT=1f29aa7a2aae8eda40a70fed79b0428153c78df8  # v1.9, the version of the installed autofirma.jar
BASE=https://raw.githubusercontent.com/ctt-gob-es/clienteafirma/$COMMIT/afirma-server-triphase-signer-core/src/main/java
OUT=target/triphase-server
SRC=$OUT/src

for file in \
  es/gob/afirma/triphase/signer/processors/TriPhasePreProcessor.java \
  es/gob/afirma/triphase/signer/processors/TriPhaseUtil.java \
  es/gob/afirma/triphase/signer/processors/PAdESTriPhasePreProcessor.java \
  es/gob/afirma/triphase/signer/processors/CAdESTriPhasePreProcessor.java \
  es/gob/afirma/triphase/signer/cades/AOCAdESTriPhaseCoSigner.java \
  es/gob/afirma/triphase/signer/cades/AOCAdESTriPhaseCounterSigner.java \
  es/gob/afirma/triphase/signer/processors/XAdESTriPhasePreProcessor.java \
  es/gob/afirma/triphase/signer/processors/XAdESTriPhaseSignerUtil.java \
  es/gob/afirma/triphase/signer/processors/FacturaETriPhasePreProcessor.java \
  es/gob/afirma/triphase/signer/xades/XAdESTriPhaseSignerServerSide.java \
  es/gob/afirma/triphase/signer/xades/XmlPreSignResult.java \
  es/gob/afirma/triphase/signer/xades/XmlPreSignException.java \
  es/gob/afirma/triphase/signer/xades/NodeDelimiter.java \
  es/gob/afirma/triphase/signer/xades/KeyHelper.java \
  es/gob/afirma/triphase/signer/xades/KeyHelperFactory.java \
  es/gob/afirma/triphase/signer/xades/KeyHelperRsa.java \
  es/gob/afirma/triphase/signer/xades/KeyHelperEcdsa.java
do
  if [ ! -f "$SRC/$file" ]; then
    mkdir -p "$SRC/$(dirname "$file")"
    curl -fsSL -o "$SRC/$file" "$BASE/$file"
  fi
done

mkdir -p "$OUT/classes"
javac -nowarn -encoding UTF-8 -cp "$JAR" -d "$OUT/classes" \
  $(find "$SRC" -name '*.java') tools/triphase-server/TriphaseServer.java
exec java -Djava.awt.headless=true -cp "$JAR:$OUT/classes" TriphaseServer "$PORT"
