package certificate.pdfbox
/*
 * Copyright 2015 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import java.io.IOException
import java.io.InputStream
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.ArrayList
import java.util.Arrays
import java.util.Enumeration

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.Store

abstract class CreateSignatureBase
/**
 * Initialize the signature creator with a keystore (pkcs12) and pin that should be used for the
 * signature.
 *
 * @param keystore is a pkcs12 keystore.
 * @param pin is the pin for the keystore / private key
 * @throws KeyStoreException if the keystore has not been initialized (loaded)
 * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
 * @throws UnrecoverableKeyException if the given password is wrong
 * @throws CertificateException if the certificate is not valid as signing time
 * @throws IOException if no certificate could be found
 */
@Throws(KeyStoreException::class, UnrecoverableKeyException::class, NoSuchAlgorithmException::class, IOException::class, CertificateException::class)
constructor(keystore: KeyStore, pin: CharArray) : SignatureInterface {
    private var privateKey: PrivateKey? = null
    private var certificateChain: Array<Certificate>? = null
    private var tsaUrl: String? = null
    /**
     * Set if external signing scenario should be used.
     * If `false`, SignatureInterface would be used for signing.
     *
     *
     * Default: `false`
     *
     * @param externalSigning `true` if external signing should be performed
     */
    var isExternalSigning: Boolean = false

    init {
        // grabs the first alias from the keystore and get the private key. An
        // alternative method or constructor could be used for setting a specific
        // alias that should be used.
        val aliases = keystore.aliases()
        var alias: String
        var cert: Certificate? = null
        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement()
            setPrivateKey(keystore.getKey(alias, pin) as PrivateKey)
            val certChain = keystore.getCertificateChain(alias) ?: continue
            setCertificateChain(certChain)
            cert = certChain[0]
            if (cert is X509Certificate) {
                // avoid expired certificate
                cert.checkValidity()
            }
            break
        }

        if (cert == null) {
            throw IOException("Could not find certificate")
        }
    }

    fun setPrivateKey(privateKey: PrivateKey) {
        this.privateKey = privateKey
    }

    fun setCertificateChain(certificateChain: Array<Certificate>) {
        this.certificateChain = certificateChain
    }

    fun setTsaUrl(tsaUrl: String?) {
        this.tsaUrl = tsaUrl
    }

    /**
     * SignatureInterface implementation.
     *
     * This method will be called from inside of the pdfbox and create the PKCS #7 signature.
     * The given InputStream contains the bytes that are given by the byte range.
     *
     * This method is for internal use only.
     *
     * Use your favorite cryptographic library to implement PKCS #7 signature creation.
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    override fun sign(content: InputStream): ByteArray {
        // cannot be done private (interface)
        try {
            val certList = ArrayList<Certificate>()
            certList.addAll(Arrays.asList(*certificateChain!!))
            val certs = JcaCertStore(certList)
            val gen = CMSSignedDataGenerator()
            val cert = org.bouncycastle.asn1.x509.Certificate.getInstance(certificateChain!![0].encoded)
            val sha1Signer = JcaContentSignerBuilder("SHA256WithRSA").build(privateKey)
            gen.addSignerInfoGenerator(JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, X509CertificateHolder(cert)))
            gen.addCertificates(certs)
            val msg = CMSProcessableInputStream(content)
            var signedData = gen.generate(msg, false)
            if (tsaUrl != null && tsaUrl!!.length > 0) {
                val validation = ValidationTimeStamp(tsaUrl)
                signedData = validation.addSignedTimeStamp(signedData)
            }
            return signedData.encoded
        } catch (e: GeneralSecurityException) {
            throw IOException(e)
        } catch (e: CMSException) {
            throw IOException(e)
        } catch (e: OperatorCreationException) {
            throw IOException(e)
        }

    }
}
