package l.keepassa.kdbx

import java.io.InputStream
import java.util.*
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal enum class Cipher(uuidStr: String) {
    AES("31c1f2e6-bf71-4350-be58-05216afc5aff"),
    TWOFISH("ad68f29f-576f-4bb9-a36a-d47af965346c"),
    CHACHA20("d6038a2b-8b6f-4cb5-a524-339a31dbb59a");

    val uuid = UUID.fromString(uuidStr)

    fun decrypt(
        input: InputStream,
        key: ByteArray,
        iv: ByteArray
    ): InputStream = when (this) {
        AES -> CipherInputStream(
            input,
            javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
                init(
                    DECRYPT_MODE,
                    SecretKeySpec(key, "AES"),
                    IvParameterSpec(iv)
                )
            })
        else -> throw UnsupportedOperationException(this.toString())
    }

    companion object {
        private val values = values()

        internal fun from(uuid: UUID) = values.find { it.uuid == uuid }
            ?: throw IllegalArgumentException(uuid.toString())
    }
}
