package certificate

import certificate.util.Encryptor
import certificate.util.KeyStoreUtil
import certificate.util.KeyVaultUtil
import certificate.util.SigningUtil
import com.microsoft.azure.AzureEnvironment
import com.microsoft.azure.CloudException
import com.microsoft.azure.credentials.ApplicationTokenCredentials
import com.microsoft.azure.management.Azure
import com.microsoft.rest.LogLevel
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*


@Suppress("UNREACHABLE_CODE")
fun main(args: Array<String>) {
    println("Hello, World")

    val certPathStr = "/Users/Far/Desktop/CerPdf/codium.pfx"
    val testCertPathStr = "/Users/Far/Desktop/CerPdf/test.pfx"
    val certPassword = "123456"
    val certOutPathStr = "/Users/Far/Desktop/CerPdf/out.pfx"

    val docInputPathStr = "/Users/Far/Desktop/CerPdf/test.docx"
    val pdfInputPathStr = "/Users/Far/Desktop/CerPdf/input.pdf"
    val xmlInputPathStr = "/Users/Far/Desktop/CerPdf/sample.xml"

    val xmlOutputPathStr = "/Users/Far/Desktop/CerPdf/sample_signed.xml"

    // Copy below and paste above to try
    return

    // Import/Export certificate from/to keyVault
    KeyVaultUtil.importPfx(certPathStr, certPassword, "codium")
    KeyVaultUtil.exportPfx("codium", certOutPathStr)

    KeyVaultUtil.exportPfx("codium", certOutPathStr, "123")

    // Sign document/pdf by KeyVault
    SigningUtil.signDocByKeyVault("codium", docInputPathStr)
    SigningUtil.signPdfByKeyVault("codium", pdfInputPathStr)
    SigningUtil.signXMLByKeyVault("codium", xmlInputPathStr, xmlOutputPathStr)

    // Sign document/pdf by Pfx
    SigningUtil.signDocByPfx(certPathStr, certPassword, docInputPathStr)
    SigningUtil.signPdfByPfx(certPathStr, certPassword, pdfInputPathStr)

    // Sign doc manually by KeyStore
    SigningUtil.signDocByKeyStore(
            KeyStoreUtil.getKeyStoreFromPfx(testCertPathStr, "123"),
            "123",
            docInputPathStr
    )

    // Sign pdf by Custom parameter
    SigningUtil.signPdfWithCustomSignature(
            KeyStoreUtil.getKeyStoreFromPfx(certPathStr, certPassword),
            certPassword,
            pdfInputPathStr,
            "/Users/Far/Desktop/CerPdf/860px-Autograph_of_Benjamin_Franklin.png",
            "Digitally signed by",
            SimpleDateFormat("yyyy.MM.dd HH:mm:ss XXX").format(Date())
    )

    // Encrypt file by AES 256
    val key = "1234567890123456789012"

    val jpgInPath = "/Users/Far/Desktop/Encrypt/test.JPG"
    val jpgOutPath = "/Users/Far/Desktop/Encrypt/test_out.JPG"

    val encInPath = "/Users/Far/Desktop/Encrypt/test.enc"
    val encOutPath = "/Users/Far/Desktop/Encrypt/test.enc"

    Encryptor.encryptFile(key, jpgInPath, encOutPath)
    Encryptor.decryptFile(key, encInPath, jpgOutPath)
}


@Throws(CloudException::class, IOException::class)
private fun authenticateToAzure(): Azure {
    //Authentication for general Azure service
    val credentials = ApplicationTokenCredentials(
            Config.AZURE_CLIENT_ID,
            Config.AZURE_TENANT_ID,
            Config.AZURE_CLIENT_SECRET,
            AzureEnvironment.AZURE
    )

    return Azure.configure()
            .withLogLevel(LogLevel.BASIC)
            .authenticate(credentials)
            .withDefaultSubscription()
}
