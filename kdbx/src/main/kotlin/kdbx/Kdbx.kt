package kdbx

import com.google.common.io.LittleEndianDataInputStream
import java.io.BufferedInputStream
import java.io.DataInput
import java.io.IOException
import java.io.InputStream
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.util.*

private fun readSignature1(input: DataInput): Int =
    when (val value = input.readInt()) {
        Kdbx.SIGNATURE_1 -> value
        else -> throw IllegalArgumentException("Unknown signature1: $value")
    }

private fun readSignature2(input: DataInput): Int =
    when (val value = input.readInt()) {
        Kdbx.SIGNATURE_2 -> value
        else -> throw IllegalArgumentException("Unknown signature2: $value")
    }

private fun readVersion(input: DataInput): Int {
    val version = input.readInt()
    if (version.and(Kdbx.FILE_VERSION_MAJOR_MASK) == Kdbx.FILE_VERSION_4) {
        return version
    }
    throw IllegalArgumentException("Unknown version: $version")
}

internal data class Kdbx(
    val signature1: Int,
    val signature2: Int,
    val version: Int,
    val headers: Headers
) {
    private fun readDatabase(
        data: LittleEndianDataInputStream,
        headers: ByteArray,
        key: ByteArray
    ) {
        val headerHashExpected = data.readFully(32)
        val headerHashActual = sha256(headers)
        if (!headerHashExpected.contentEquals(headerHashActual)) {
            throw IllegalArgumentException(
                "Header SHA-256 mismatch" +
                        ", expected ${headerHashExpected.toHexString()}" +
                        ", got ${headerHashActual.toHexString()}"
            )
        }

        val hmacKey = sha512(
            this.headers.masterSeed.toByteArray(),
            this.headers.kdf.transform(key),
            byteArrayOf(1)
        )
        val hmacKeySha = sha512(
            (-1L).encode(LITTLE_ENDIAN),
            hmacKey
        )
        val headerMacExpected = data.readFully(32)
        val headerMacActual = hmacSha256(hmacKeySha, headers)
        if (!headerMacExpected.contentEquals(headerMacActual)) {
            throw IllegalArgumentException(
                "Header HMAC mismatch" +
                        ", expected ${headerMacExpected.toHexString()}" +
                        ", actual ${headerMacActual.toHexString()}"
            ) // TODO bad credentials message
        }

        HmacBlockInputStream(data, hmacKey).readAllBytes()
    }

    companion object {
        internal const val SIGNATURE_1: Int = 0x9aa2d903.toInt()
        internal const val SIGNATURE_2: Int = 0xb54bfb67.toInt()
        internal const val FILE_VERSION_MAJOR_MASK: Int = 0xffff0000.toInt()
        internal const val FILE_VERSION_4: Int = 0x00040000
        internal const val VARIANT_VERSION_MAJOR_MASK: Short = 0xff00.toShort()
        internal const val VARIANT_VERSION: Short = 0x0100

        internal fun read(
            input: InputStream,
            passwordHash: ByteArray?,
            keyFileHash: ByteArray?
        ): Kdbx {
            val buffer = BufferingInputStream(input)
            val data = LittleEndianDataInputStream(buffer)
            buffer.mark(Int.MAX_VALUE)

            val signature1 = readSignature1(data)
            val signature2 = readSignature2(data)
            val version = readVersion(data)
            val headers = Headers.read(data)
            val kdbx = Kdbx(
                signature1,
                signature2,
                version,
                headers
            )

            val headerBytes = buffer.drainFromMark()
            val key = sha256(
                *arrayOf(passwordHash, keyFileHash)
                    .filterNotNull()
                    .toTypedArray()
            )
            kdbx.readDatabase(data, headerBytes, key)
            return kdbx
        }
    }
}

private class BufferingInputStream(input: InputStream) :
    BufferedInputStream(input) {

    fun drainFromMark(): ByteArray {
        if (markpos < 0) {
            throw IOException("Mark not set")
        }
        val bytes = Arrays.copyOfRange(buf, markpos, pos)
        reset()
        skip(bytes.size.toLong())
        return bytes
    }
}