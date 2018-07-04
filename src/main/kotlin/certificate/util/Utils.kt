package certificate.util

import com.sun.org.apache.xml.internal.security.signature.XMLSignature
import org.apache.xml.security.algorithms.MessageDigestAlgorithm
import org.w3c.dom.Document
import xades4j.algorithms.Algorithm
import xades4j.algorithms.CanonicalXMLWithoutComments
import xades4j.algorithms.GenericAlgorithm
import xades4j.providers.AlgorithmsProviderEx
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

fun parseXmlFile(fileName: String): Document {
    val factory = DocumentBuilderFactory.newInstance()
    factory.isNamespaceAware = true

    return factory
            .newDocumentBuilder()
            .parse(File(fileName))
}

class RdEtaxAlgorithmProvider : AlgorithmsProviderEx {
    override fun getSignatureAlgorithm(p0: String?): Algorithm = GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512)

    override fun getCanonicalizationAlgorithmForSignature(): Algorithm = CanonicalXMLWithoutComments()

    override fun getCanonicalizationAlgorithmForTimeStampProperties(): Algorithm = CanonicalXMLWithoutComments()

    override fun getDigestAlgorithmForDataObjsReferences(): String = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512

    override fun getDigestAlgorithmForReferenceProperties(): String = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512

    override fun getDigestAlgorithmForTimeStampProperties(): String = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512

}