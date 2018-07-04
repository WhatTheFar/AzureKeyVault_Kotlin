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

import org.apache.pdfbox.io.IOUtils
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.Attributes
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.SignerInformationStore

import java.io.IOException
import java.io.InputStream
import java.net.MalformedURLException
import java.net.URL
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.ArrayList

/**
 * This class wraps the TSAClient and the work that has to be done with it. Like Adding Signed
 * TimeStamps to a signature, or creating a CMS timestamp attribute (with a signed timestamp)
 *
 * @author Others
 * @author Alexis Suter
 */
class ValidationTimeStamp
/**
 * @param tsaUrl The url where TS-Request will be done.
 * @throws NoSuchAlgorithmException
 * @throws MalformedURLException
 */
@Throws(NoSuchAlgorithmException::class, MalformedURLException::class)
constructor(tsaUrl: String?) {
    private var tsaClient: TSAClient? = null

    init {
        if (tsaUrl != null) {
            val digest = MessageDigest.getInstance("SHA-256")
            this.tsaClient = TSAClient(URL(tsaUrl), null, null, digest)
        }
    }

    /**
     * Creates a signed timestamp token by the given input stream.
     *
     * @param content InputStream of the content to sign
     * @return the byte[] of the timestamp token
     * @throws IOException
     */
    @Throws(IOException::class)
    fun getTimeStampToken(content: InputStream): ByteArray {
        return tsaClient!!.getTimeStampToken(IOUtils.toByteArray(content))
    }

    /**
     * Extend cms signed data with TimeStamp first or to all signers
     *
     * @param signedData Generated CMS signed data
     * @return CMSSignedData Extended CMS signed data
     * @throws IOException
     */
    @Throws(IOException::class)
    fun addSignedTimeStamp(signedData: CMSSignedData): CMSSignedData {
        val signerStore = signedData.signerInfos
        val newSigners = ArrayList<SignerInformation>()

        for (signer in signerStore.signers) {
            // This adds a timestamp to every signer (into his unsigned attributes) in the signature.
            newSigners.add(signTimeStamp(signer))
        }

        // Because new SignerInformation is created, new SignerInfoStore has to be created
        // and also be replaced in signedData. Which creates a new signedData object.
        return CMSSignedData.replaceSigners(signedData, SignerInformationStore(newSigners))
    }

    /**
     * Extend CMS Signer Information with the TimeStampToken into the unsigned Attributes.
     *
     * @param signer information about signer
     * @return information about SignerInformation
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun signTimeStamp(signer: SignerInformation): SignerInformation {
        val unsignedAttributes = signer.unsignedAttributes

        var vector = ASN1EncodableVector()
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector()
        }

        val token = tsaClient!!.getTimeStampToken(signer.signature)
        val oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
        val signatureTimeStamp = Attribute(oid,
                DERSet(ASN1Primitive.fromByteArray(token)))

        vector.add(signatureTimeStamp)
        val signedAttributes = Attributes(vector)

        // There is no other way changing the unsigned attributes of the signer information.
        // result is never null, new SignerInformation always returned,
        // see source code of replaceUnsignedAttributes
        return SignerInformation.replaceUnsignedAttributes(signer, AttributeTable(signedAttributes))
    }
}
