package kdbx

import java.nio.channels.ReadableByteChannel

private fun readSignature1(input: ReadableByteChannel): Int =
    input.read32le { it == Kdbx.SIGNATURE_1 }

private fun readSignature2(input: ReadableByteChannel): Int =
    input.read32le { it == Kdbx.SIGNATURE_2 }

private fun readVersion(input: ReadableByteChannel): Int = input.read32le {
    it.and(Kdbx.FILE_VERSION_MAJOR_MASK) == Kdbx.FILE_VERSION_4
}


internal data class Kdbx(
    val signature1: Int,
    val signature2: Int,
    val version: Int,
    val headers: Headers
) {
    companion object {
        internal const val SIGNATURE_1: Int = 0x9aa2d903.toInt()
        internal const val SIGNATURE_2: Int = 0xb54bfb67.toInt()
        internal const val FILE_VERSION_MAJOR_MASK: Int = 0xffff0000.toInt()
        internal const val FILE_VERSION_4: Int = 0x00040000
        internal const val VARIANT_VERSION_MAJOR_MASK: Short = 0xff00.toShort()
        internal const val VARIANT_VERSION: Short = 0x0100

        internal fun read(input: ReadableByteChannel): Kdbx {
            val signature1 = readSignature1(input)
            val signature2 = readSignature2(input)
            val version = readVersion(input)
            val headers = Headers.read(input)
            return Kdbx(
                signature1,
                signature2,
                version,
                headers
            )
        }
    }
}
