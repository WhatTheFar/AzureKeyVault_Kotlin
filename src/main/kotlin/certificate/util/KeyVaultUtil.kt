package certificate.util

import certificate.Config
import certificate.common.getAliasWithPrivateKey
import certificate.common.getKeyStoreFromCertificate
import certificate.keyvault.KeyVaultAuthenticator
import com.microsoft.azure.keyvault.requests.ImportCertificateRequest
import sun.misc.BASE64Encoder
import java.io.*
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyStore
import java.util.*

object KeyVaultUtil {

    fun exportPfx(certificateName: String, outPathStr: String, certificatePassword: String? = null) {

        val kvClient = KeyVaultAuthenticator.authenticatedClient

        val cerBundle = kvClient.getCertificate(Config.VAULT_BASE_URL, certificateName)
        val secretBundle = kvClient.getSecret(cerBundle.sid())

        val decodedSecretValue = Base64.getDecoder().decode(secretBundle.value())

        if (certificatePassword != null) {
            val keyStore = KeyStore.getInstance("PKCS12")
                    .apply {
                        load(ByteArrayInputStream(decodedSecretValue), "".toCharArray())
                    }

            val alias = keyStore.getAliasWithPrivateKey()
            val certificate = keyStore.getCertificate(alias)
            // azure will always have empty password for private key
            val key = keyStore.getKey(alias, "".toCharArray())

            keyStore.setKeyEntry(alias, key, certificatePassword.toCharArray(), arrayOf(certificate))

            keyStore.store(FileOutputStream(outPathStr), certificatePassword.toCharArray())
        } else {
            Files.write(Paths.get(outPathStr), decodedSecretValue)
        }
    }

    fun importPfx(certPathStr: String, certPassword: String, certificateName: String) {

        val kvClient = KeyVaultAuthenticator.authenticatedClient

        val myPfxEncodedAsBase64 = FileInputStream(certPathStr)
                .use {
                    val outBuffer = ByteArrayOutputStream()
                    val inBuffer = ByteArray(512)
                    var read = 0
                    while ({ read = it.read(inBuffer); read }() != -1) {
                        outBuffer.write(inBuffer, 0, read)
                    }
                    return@use BASE64Encoder().encode(outBuffer.toByteArray())
                }

        kvClient.importCertificate(
                ImportCertificateRequest
                        .Builder(Config.VAULT_BASE_URL, certificateName, myPfxEncodedAsBase64)
                        .apply {
                            withPassword(certPassword)
                        }
                        .build()
        )
    }
}