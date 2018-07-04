package certificate.common

import com.microsoft.azure.keyvault.KeyVaultClient
import com.microsoft.azure.keyvault.models.CertificateBundle
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.util.*

fun KeyVaultClient.getKeyStoreFromCertificate(vaultBaseUrl: String, certificateName: String): KeyStore {

    val certificateBundle: CertificateBundle? = getCertificate(vaultBaseUrl, certificateName)
    val secretBundle = getSecret(certificateBundle?.sid())

    val decodedSecretValue = Base64.getDecoder().decode(secretBundle.value())
    return KeyStore.getInstance("PKCS12")
            .apply {
                load(ByteArrayInputStream(decodedSecretValue), "".toCharArray())
            }
}
