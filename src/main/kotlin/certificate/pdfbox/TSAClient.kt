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

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.apache.pdfbox.io.IOUtils
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.tsp.*

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.URL
import java.net.URLConnection
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Time Stamping Authority (TSA) Client [RFC 3161].
 * @author Vakhtang Koroghlishvili
 * @author John Hewson
 */
class TSAClient
/**
 *
 * @param url the URL of the TSA service
 * @param username user name of TSA
 * @param password password of TSA
 * @param digest the message digest to use
 */
(private val url: URL, private val username: String?, private val password: String?, private val digest: MessageDigest) {

    /**
     *
     * @param messageImprint imprint of message contents
     * @return the encoded time stamp token
     * @throws IOException if there was an error with the connection or data from the TSA server,
     * or if the time stamp response could not be validated
     */
    @Throws(IOException::class)
    fun getTimeStampToken(messageImprint: ByteArray): ByteArray {
        digest.reset()
        val hash = digest.digest(messageImprint)

        // 32-bit cryptographic nonce
        val random = SecureRandom()
        val nonce = random.nextInt()

        // generate TSA request
        val tsaGenerator = TimeStampRequestGenerator()
        tsaGenerator.setCertReq(true)
        val oid = getHashObjectIdentifier(digest.algorithm)
        val request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce.toLong()))

        // get TSA response
        val tsaResponse = getTSAResponse(request.encoded)

        val response: TimeStampResponse
        try {
            response = TimeStampResponse(tsaResponse)
            response.validate(request)
        } catch (e: TSPException) {
            throw IOException(e)
        }

        val token = response.timeStampToken ?: throw IOException("Response does not have a time stamp token")

        return token.encoded
    }

    // gets response data for the given encoded TimeStampRequest data
    // throws IOException if a connection to the TSA cannot be established
    @Throws(IOException::class)
    private fun getTSAResponse(request: ByteArray): ByteArray {
        LOG.debug("Opening connection to TSA server")

        // todo: support proxy servers
        val connection = url.openConnection()
        connection.doOutput = true
        connection.doInput = true
        connection.setRequestProperty("Content-Type", "application/timestamp-query")

        LOG.debug("Established connection to TSA server")

        if (username != null && password != null && !username.isEmpty() && !password.isEmpty()) {
            connection.setRequestProperty(username, password)
        }

        // read response
        var output: OutputStream? = null
        try {
            output = connection.getOutputStream()
            output!!.write(request)
        } finally {
            IOUtils.closeQuietly(output)
        }

        LOG.debug("Waiting for response from TSA server")

        var input: InputStream? = null
        val response: ByteArray
        try {
            input = connection.getInputStream()
            response = IOUtils.toByteArray(input!!)
        } finally {
            IOUtils.closeQuietly(input)
        }

        LOG.debug("Received response from TSA server")

        return response
    }

    // returns the ASN.1 OID of the given hash algorithm
    private fun getHashObjectIdentifier(algorithm: String): ASN1ObjectIdentifier {
        when (algorithm) {
            "MD2" -> return ASN1ObjectIdentifier(PKCSObjectIdentifiers.md2.id)
            "MD5" -> return ASN1ObjectIdentifier(PKCSObjectIdentifiers.md5.id)
            "SHA-1" -> return ASN1ObjectIdentifier(OIWObjectIdentifiers.idSHA1.id)
            "SHA-224" -> return ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha224.id)
            "SHA-256" -> return ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha256.id)
            "SHA-384" -> return ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha384.id)
            "SHA-512" -> return ASN1ObjectIdentifier(NISTObjectIdentifiers.id_sha512.id)
            else -> return ASN1ObjectIdentifier(algorithm)
        }
    }

    companion object {
        private val LOG = LogFactory.getLog(TSAClient::class.java)
    }
}
