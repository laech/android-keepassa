package l.keepassa.kdbx

import com.google.common.collect.ImmutableList
import com.google.common.collect.ImmutableMap
import java.io.InputStream

internal data class Kdbx(
    val signature1: Int,
    val signature2: Int,
    val version: Int,
    val headers: Headers,
    val innerHeaders: InnerHeaders,
    val content: Node
)

internal data class Headers(
    val compression: Compression,
    val cipher: Cipher,
    val masterSeed: ByteString,
    val encryptionIv: ByteString,
    val kdf: Kdf,
    val publicCustomData: ImmutableMap<String, Any>
)

internal data class InnerHeaders(
    val innerRandomStreamKey: ByteString,
    val binaries: ImmutableList<Binary>
)

internal enum class Compression {
    // The ordinal of each value is also their corresponding ID
    NONE,
    GZIP;

    companion object {
        private val values = values()

        internal fun from(id: Int) = values.getOrNull(id)
            ?: throw IllegalArgumentException(id.toString())
    }
}

fun kdbxOpen(input: InputStream, password: String): String {
    return parseKdbx(input, password, null).content.toString()
}
