package certificate.util

import java.io.File
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Encryptor {
    fun decrypt(key: String, value: ByteArray): ByteArray? {
        try {
            val decodedValue = Base64.getDecoder().decode(value)

            val skeySpec = SecretKeySpec(key.toByteArray(), "AES")
            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

            val iv = decodedValue.sliceArray(0..15)
            val ivParams = IvParameterSpec(iv)

            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParams)

            val encryptedValue = decodedValue.sliceArray(16..(decodedValue.size - 1))

            return cipher.doFinal(encryptedValue)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    fun encrypt(key: String, value: ByteArray): ByteArray? {
        try {
            val skeySpec = SecretKeySpec(key.toByteArray(), "AES")
            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

            val iv = ByteArray(cipher.blockSize)
                    .apply {
                        SecureRandom().nextBytes(this)
                    }
            val ivParams = IvParameterSpec(iv)

            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParams)

            val encrypted = cipher.doFinal(value)

            return Base64.getEncoder().encode(iv + encrypted)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    fun encryptFile(key: String, inPath: String, outPath: String) {
        val fileBytes = File(inPath).readBytes()
        val encrypted = encrypt(key, fileBytes)
        File(outPath).writeBytes(encrypted!!)
    }

    fun decryptFile(key: String, inPath: String, outPath: String) {
        val fileBytes = File(inPath).readBytes()
        val decrypted = decrypt(key, fileBytes)
        File(outPath).writeBytes(decrypted!!)
    }
}