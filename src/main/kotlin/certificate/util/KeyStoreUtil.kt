package certificate.util

import com.microsoft.azure.keyvault.KeyVaultClient
import java.io.ByteArrayInputStream
import java.io.FileInputStream
import java.security.KeyStore
import java.util.*

object KeyStoreUtil {

    fun getKeyStoreFromKeyVault(kvClient: KeyVaultClient, vaultBaseUrl: String, certificateName: String): KeyStore {

        val certificateBundle = kvClient.getCertificate(vaultBaseUrl, certificateName)
        val secretBundle = kvClient.getSecret(certificateBundle.sid())

        val decodedSecretValue = Base64.getDecoder().decode(secretBundle.value())
        return KeyStore.getInstance("PKCS12")
                .apply {
                    load(ByteArrayInputStream(decodedSecretValue), "".toCharArray())
                }
    }

    fun getKeyStoreFromPfx(certPathStr: String, certPassword: String) =
            KeyStore.getInstance("PKCS12").apply {
                FileInputStream(certPathStr).use {
                    load(it, certPassword.toCharArray())
                }
            }

}