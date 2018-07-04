package certificate.xades

import certificate.common.getAliasWithPrivateKey
import xades4j.providers.KeyingDataProvider
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.*

class KeyStoreKeyingDataProvider(
        private val keyStore: KeyStore,
        private val keyPassword: String
) : KeyingDataProvider {

    private val alias: String? by lazy {
        keyStore.getAliasWithPrivateKey()
    }

    private val certificate: X509Certificate by lazy {
        keyStore.getCertificate(alias) as X509Certificate
    }

    private val privateKey: PrivateKey by lazy {
        keyStore.getKey(alias, keyPassword.toCharArray()) as PrivateKey
    }


    override fun getSigningCertificateChain(): MutableList<X509Certificate> = Collections.singletonList(certificate)


    override fun getSigningKey(p0: X509Certificate?): PrivateKey = privateKey

}