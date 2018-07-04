package certificate.pdfbox
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions

import java.io.*
import java.security.*
import java.security.cert.CertificateException
import java.util.Calendar

/**
 * An example for signing a PDF with bouncy castle.
 * A keystore can be created with the java keytool, for example:
 *
 * `keytool -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365
 * -v -keyalg RSA -keystore keystore.p12 `
 *
 * @author Thomas Chojecki
 * @author Vakhtang Koroghlishvili
 * @author John Hewson
 */
class CreateSignature
/**
 * Initialize the signature creator with a keystore and certficate password.
 *
 * @param keystore the pkcs12 keystore containing the signing certificate
 * @param pin the password for recovering the key
 * @throws KeyStoreException if the keystore has not been initialized (loaded)
 * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
 * @throws UnrecoverableKeyException if the given password is wrong
 * @throws CertificateException if the certificate is not valid as signing time
 * @throws IOException if no certificate could be found
 */
@Throws(KeyStoreException::class, UnrecoverableKeyException::class, NoSuchAlgorithmException::class, CertificateException::class, IOException::class)
constructor(keystore: KeyStore, pin: CharArray) : CreateSignatureBase(keystore, pin) {

    /**
     * Signs the given PDF file. Alters the original file on disk.
     * @param file the PDF file to sign
     * @throws IOException if the file could not be read or written
     */
    @Throws(IOException::class)
    fun signDetached(file: File) {
        signDetached(file, file, null)
    }

    /**
     * Signs the given PDF file.
     * @param inFile input PDF file
     * @param outFile output PDF file
     * @param tsaUrl optional TSA url
     * @throws IOException if the input file could not be read
     */
    @Throws(IOException::class)
    @JvmOverloads
    fun signDetached(inFile: File?, outFile: File, tsaUrl: String? = null) {
        if (inFile == null || !inFile.exists()) {
            throw FileNotFoundException("Document for signing does not exist")
        }

        // TODO:
        setTsaUrl(tsaUrl)
//        setTsaUrl(tsaUrl!!)

        // sign
        FileOutputStream(outFile).use { fos -> PDDocument.load(inFile).use { doc -> signDetached(doc, fos) } }
    }

    @Throws(IOException::class)
    fun signDetached(document: PDDocument, output: OutputStream) {
        val accessPermissions = SigUtils.getMDPPermission(document)
        if (accessPermissions == 1) {
            throw IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary")
        }

        // create signature dictionary
        val signature = PDSignature()
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED)
        signature.name = "Example User"
        signature.location = "Los Angeles, CA"
        signature.reason = "Testing"
        // TODO extract the above details from the signing certificate? Reason as a parameter?

        // the signing date, needed for valid signature
        signature.signDate = Calendar.getInstance()

        // Optional: certify
        if (accessPermissions == 0) {
            SigUtils.setMDPPermission(document, signature, 2)
        }

        if (isExternalSigning) {
            println("Sign externally...")
            document.addSignature(signature)
            val externalSigning = document.saveIncrementalForExternalSigning(output)
            // invoke external signature service
            val cmsSignature = sign(externalSigning.content)
            // set signature bytes received from the service
            externalSigning.setSignature(cmsSignature)
        } else {
            val signatureOptions = SignatureOptions()
            // Size can vary, but should be enough for purpose.
            signatureOptions.preferredSignatureSize = SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2
            // register signature dictionary and sign interface
            document.addSignature(signature, this, signatureOptions)

            // write incremental (only for signing purpose)
            document.saveIncremental(output)
        }
    }

    companion object {

        @Throws(IOException::class, GeneralSecurityException::class)
        @JvmStatic
        fun main(args: Array<String>) {
            if (args.size < 3) {
                usage()
                System.exit(1)
            }

            var tsaUrl: String? = null
            var externalSig = false
            var i = 0
            while (i < args.size) {
                if (args[i] == "-tsa") {
                    i++
                    if (i >= args.size) {
                        usage()
                        System.exit(1)
                    }
                    tsaUrl = args[i]
                }
                if (args[i] == "-e") {
                    externalSig = true
                }
                i++
            }

            // load the keystore
            val keystore = KeyStore.getInstance("PKCS12")
            val password = args[1].toCharArray() // TODO use Java 6 java.io.Console.readPassword
            keystore.load(FileInputStream(args[0]), password)
            // TODO alias command line argument

            // sign PDF
            val signing = CreateSignature(keystore, password)
            signing.isExternalSigning = externalSig

            val inFile = File(args[2])
            val name = inFile.name
            val substring = name.substring(0, name.lastIndexOf('.'))

            val outFile = File(inFile.parent, substring + "_signed.pdf")
            signing.signDetached(inFile, outFile, tsaUrl)
        }

        private fun usage() {
            System.err.println("usage: java " + CreateSignature::class.java.name + " " +
                    "<pkcs12_keystore> <password> <pdf_to_sign>\n" + "" +
                    "options:\n" +
                    "  -tsa <url>    sign timestamp using the given TSA server\n" +
                    "  -e            sign using external signature creation scenario")
        }
    }
}
/**
 * Signs the given PDF file.
 * @param inFile input PDF file
 * @param outFile output PDF file
 * @throws IOException if the input file could not be read
 */
