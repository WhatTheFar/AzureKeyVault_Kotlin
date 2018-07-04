package certificate.util

import certificate.Config
import certificate.common.getAliasWithPrivateKey
import certificate.common.getKeyStoreFromCertificate
import certificate.keyvault.KeyVaultAuthenticator
import certificate.pdfbox.CreateSignature
import certificate.pdfbox.CreateVisibleCustomSignature
import certificate.pdfbox.CreateVisibleTimeStampSignature
import certificate.xades.KeyStoreKeyingDataProvider
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.poi.openxml4j.opc.OPCPackage
import org.apache.poi.openxml4j.opc.PackageAccess
import org.apache.poi.poifs.crypt.dsig.SignatureConfig
import org.apache.poi.poifs.crypt.dsig.SignatureInfo
import xades4j.production.Enveloped
import xades4j.production.XadesBesSigningProfile
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider
import java.awt.geom.Rectangle2D
import java.io.File
import java.nio.file.Paths
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.*
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

object SigningUtil {


    fun signDocByKeyVault(certificateName: String, inputPathStr: String) {
        signDocByKeyStore(
                KeyVaultAuthenticator
                        .authenticatedClient
                        .getKeyStoreFromCertificate(Config.VAULT_BASE_URL, certificateName),
                "",
                inputPathStr
        )
    }

    fun signDocByPfx(certPathStr: String, certPassword: String, inputPathStr: String) {
        signDocByKeyStore(
                KeyStoreUtil.getKeyStoreFromPfx(certPathStr, certPassword),
                certPassword,
                inputPathStr
        )
    }

    fun signDocByKeyStore(keyStore: KeyStore, keyPassword: String, inputPathStr: String) {

        val alias = keyStore.getAliasWithPrivateKey()
        val key = keyStore.getKey(alias, keyPassword.toCharArray())
        val x509 = keyStore.getCertificate(alias) as X509Certificate

        val pkg = OPCPackage.open(inputPathStr, PackageAccess.READ_WRITE)
        val signatureConfig = SignatureConfig()
                .apply {
                    this.key = key as PrivateKey
                    signingCertificateChain = Collections.singletonList(x509)
                    opcPackage = pkg
                }

        // adding the signature document to the package
        val si = SignatureInfo()
                .apply {
                    this.signatureConfig = signatureConfig
                }
        si.confirmSignature()
        // optionally verify the generated signature
        val b = si.verifySignature()

        assert(b)
        // write the changes back to disc
        pkg.close()
    }

    fun signPdfByKeyVault(certificateName: String, inputPathStr: String) {
        signPdfByKeyStore(
                KeyVaultAuthenticator
                        .authenticatedClient
                        .getKeyStoreFromCertificate(Config.VAULT_BASE_URL, certificateName),
                "",
                inputPathStr
        )
    }

    fun signPdfByPfx(certPathStr: String, certPassword: String, inputPathStr: String) {
        signPdfByKeyStore(
                KeyStoreUtil.getKeyStoreFromPfx(certPathStr, certPassword),
                certPassword,
                inputPathStr
        )
    }

    fun signPdfByKeyStore(keyStore: KeyStore, keyPassword: String, inputPathStr: String) {

        val inFile = File(inputPathStr)
        val outputTempPathStr = inFile.name.let { it.substring(0, it.lastIndexOf('.')) + "_temp.pdf" }

        // Sign PDF
        val signing = CreateSignature(keyStore, keyPassword.toCharArray())
        signing.isExternalSigning = false

        val outFile = File(outputTempPathStr)
        signing.signDetached(inFile, outFile)

        outFile.renameTo(inFile)
    }

    fun signPdfWithTimeStamp(keyStore: KeyStore, keyPassword: String, inputPathStr: String, imgPathStr: String? = null) {
        val inputFile = File(inputPathStr)
        val filePathStr = inputPathStr.substring(0, inputPathStr.lastIndexOf('.'))
        val outputFile = File("${filePathStr}_signed.pdf")

        val signing = CreateVisibleTimeStampSignature(keyStore, keyPassword.toCharArray().clone())
        signing.isExternalSigning = false
        signing.imageFile = imgPathStr?.let(::File)

        var x = 10f
        var y = 10f
        val w = 150f
        val h = 50f
        PDDocument.load(inputFile).use {
            val page = it.getPage(0)
            val pageRect = page.cropBox
            x = pageRect.width - x - w
            y = pageRect.height - y - h
        }
        val humanRect = Rectangle2D.Float(x, y, w, h)
        signing.signPDF(inputFile, outputFile, humanRect, null, "Signature1")

        // Rename file
//        outputFile.renameTo(inputFile)

    }

    fun signPdfWithCustomSignature(
            keyStore: KeyStore,
            keyPassword: String,
            inputPathStr: String,
            imgPathStr: String? = null,
            line1: String? = null,
            line2: String? = null
    ) {
        val inputFile = File(inputPathStr)
        val filePathStr = inputPathStr.substring(0, inputPathStr.lastIndexOf('.'))
        val outputFile = File("${filePathStr}_signed.pdf")

        val marginRight = 10f
        val marginBottom = 10f
        val width = 140f
        val imageHeight = 50f
        val fontSize = 13f
        // should greater than fontSize * 2
        val textHeight = 30f
        val height = imageHeight + textHeight

        val signing =
                CreateVisibleCustomSignature(keyStore, keyPassword.toCharArray().clone())
                        .apply {
                            isExternalSigning = false
                            imageFile = imgPathStr?.let(::File)
                            this.line1 = line1
                            this.line2 = line2
                            this.imageHeight = imageHeight
                            this.fontSize = fontSize
                            this.fontPath = Config.FONT_PATH
                        }


        var x = 0f
        var y = 0f
        PDDocument.load(inputFile).use {
            val page = it.getPage(0)
            val pageRect = page.cropBox
            x = pageRect.width - marginRight - width
            y = pageRect.height - marginBottom - height
        }
        val humanRect = Rectangle2D.Float(x, y, width, height)
        signing.signPDF(inputFile, outputFile, humanRect, null, "Signature")

        // Rename file
//        outputFile.renameTo(inputFile)

    }

    fun signXMLByKeyVault(certificateName: String, inputPathStr: String, outputPath: String? = null) {
        signXMLByKeyStore(
                KeyVaultAuthenticator
                        .authenticatedClient
                        .getKeyStoreFromCertificate(Config.VAULT_BASE_URL, certificateName),
                "",
                inputPathStr,
                outputPath
        )
    }

    fun signXMLByKeyStore(keyStore: KeyStore, keyPassword: String, inputPathStr: String, outputPathStr: String? = null) {

        val kdp = KeyStoreKeyingDataProvider(keyStore, keyPassword)

        val xmlOutputPathStr = outputPathStr ?: inputPathStr


        val doc = parseXmlFile(inputPathStr)
        val elemToSign = doc.documentElement

        // Digitally signing the document
        val signer = XadesBesSigningProfile(kdp)
                .withAlgorithmsProviderEx(RdEtaxAlgorithmProvider())
                .newSigner()
        Enveloped(signer).sign(elemToSign)

        // Signed output file is produced
        val transformer = TransformerFactory.newInstance().newTransformer()
        val source = DOMSource(doc)
        val fileOutput = File(xmlOutputPathStr)
        fileOutput.createNewFile()
        val result = StreamResult(fileOutput)
        transformer.transform(source, result)
    }
}