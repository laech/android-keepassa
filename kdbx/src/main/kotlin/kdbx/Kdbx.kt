package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.LITTLE_ENDIAN

private fun readSignature1(buffer: ByteBuffer): Int =
    when (val value = buffer.int) {
        Kdbx.SIGNATURE_1 -> value
        else -> throw IllegalArgumentException("Unknown signature1: $value")
    }

private fun readSignature2(buffer: ByteBuffer): Int =
    when (val value = buffer.int) {
        Kdbx.SIGNATURE_2 -> value
        else -> throw IllegalArgumentException("Unknown signature2: $value")
    }

private fun readVersion(buffer: ByteBuffer): Int {
    val version = buffer.int
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
    fun readDatabase(
        buffer: ByteBuffer,
        headerBuffer: ByteBuffer,
        key: ByteArray
    ) {
        val finalKey = sha256(
            headers.masterSeed.toByteArray(),
            headers.kdfParameters!!.transform(key)
        )
        val expectedHeaderHash = buffer.getByteArray(32)
        val actualHeaderHash = sha256(headerBuffer.getByteArray())
        if (!expectedHeaderHash.contentEquals(actualHeaderHash)) {
            throw IllegalArgumentException(
                "Header SHA-256 mismatch" +
                        ", expected ${expectedHeaderHash.toHexString()}" +
                        ", got ${actualHeaderHash.toHexString()}"
            )
        }

        val hmac = buffer.getByteArray(32)
    }

    companion object {
        internal const val SIGNATURE_1: Int = 0x9aa2d903.toInt()
        internal const val SIGNATURE_2: Int = 0xb54bfb67.toInt()
        internal const val FILE_VERSION_MAJOR_MASK: Int = 0xffff0000.toInt()
        internal const val FILE_VERSION_4: Int = 0x00040000
        internal const val VARIANT_VERSION_MAJOR_MASK: Short = 0xff00.toShort()
        internal const val VARIANT_VERSION: Short = 0x0100

        internal fun read(buffer: ByteBuffer, key: ByteArray): Kdbx =
            buffer.slice().order(LITTLE_ENDIAN).run {
                mark()
                val signature1 = readSignature1(this)
                val signature2 = readSignature2(this)
                val version = readVersion(this)
                val headers = Headers.read(this)
                val kdbx = Kdbx(
                    signature1,
                    signature2,
                    version,
                    headers
                )
                val headerLength = position()
                rewind()

                val headerBuffer = getByteBuffer(headerLength)
                kdbx.readDatabase(this, headerBuffer, key)
                kdbx
            }
    }
}
