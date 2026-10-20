#!/usr/bin/env python3
"""Verifies the signatures of ODF documents with LibreOffice, to cross-check
the documents signed by autofirma-rs.

Usage: tools/lo_verify.py DOCUMENT...

Starts a headless LibreOffice with a throwaway profile and asks its
DocumentDigitalSignatures service to verify every document. Prints one line
per signature and exits with 0 when every document has signatures, all of
them cryptographically valid and covering the whole document. Certificate
trust (our test CA) is not checked.

Needs LibreOffice and its Python UNO bridge (python3-uno). Under a sandboxed
shell, run it with a clean environment (env -i PATH=/usr/bin:/bin HOME=$HOME).

OOXML documents are read too, but LibreOffice always reports their signatures
as partial, and distribution builds linked to the system xmlsec1 (without
LibreOffice's patch for the OPC relationship transform) cannot verify them at
all, not even AutoFirma's: use tools/AfirmaValidate.java for OOXML.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

import uno
from com.sun.star.beans import PropertyValue
from com.sun.star.connection import NoConnectException

READ = 1  # com.sun.star.embed.ElementModes.READ


def connect(pipe):
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    for _ in range(120):
        try:
            return resolver.resolve(
                f"uno:pipe,name={pipe};urp;StarOffice.ComponentContext")
        except NoConnectException:
            time.sleep(0.5)
    raise SystemExit("LibreOffice did not start")


def verify(ctx, path):
    smgr = ctx.ServiceManager
    url = uno.systemPathToFileUrl(os.path.abspath(path))
    # Plain ZIP storage, as LibreOffice opens documents to sign them: package
    # storages hide META-INF and the relationship parts.
    storage_format = PropertyValue()
    storage_format.Name = "StorageFormat"
    storage_format.Value = "ZipFormat"
    factory = smgr.createInstanceWithContext("com.sun.star.embed.StorageFactory", ctx)
    # The third argument must be a sequence<PropertyValue>, not sequence<any>.
    storage = uno.invoke(factory, "createInstanceWithArguments", (
        (url, READ, uno.Any("[]com.sun.star.beans.PropertyValue", (storage_format,))),))
    signatures = smgr.createInstanceWithArgumentsAndContext(
        "com.sun.star.security.DocumentDigitalSignatures", ("1.2", True), ctx)
    return signatures.verifyDocumentContentSignatures(storage, None)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    profile = tempfile.mkdtemp(prefix="lo_verify_")
    pipe = f"lo_verify_{os.getpid()}"
    office = subprocess.Popen(
        ["soffice", "--headless", "--norestore", "--nologo", "--nodefault",
         f"-env:UserInstallation={uno.systemPathToFileUrl(profile)}",
         f"--accept=pipe,name={pipe};urp;"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok = True
    try:
        ctx = connect(pipe)
        for path in sys.argv[1:]:
            infos = verify(ctx, path)
            if not infos:
                print(f"{path}: no signatures")
                ok = False
            for info in infos:
                valid = info.SignatureIsValid and not info.PartialDocumentSignature
                ok &= valid
                print(f"{path}: {'OK' if valid else 'KO'} valid={info.SignatureIsValid} "
                      f"partial={info.PartialDocumentSignature} signer={info.Signer.SubjectName}")
    finally:
        office.terminate()
        try:
            office.wait(timeout=20)
        except subprocess.TimeoutExpired:
            office.kill()
        shutil.rmtree(profile, ignore_errors=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
