package kdbx

import java.nio.ByteBuffer

internal enum class Compression {

    // The ordinal of each value is also their corresponding ID
    NONE,
    GZIP;

    companion object {
        private val values = values()

        private fun fromId(id: Int) = values.getOrNull(id)
            ?: throw IllegalArgumentException(id.toString())

        fun fromIdBuffer(buffer: ByteBuffer): Compression = when {
            buffer.remaining() != 4 -> throw IllegalArgumentException()
            else -> fromId(buffer.int)
        }
    }
}
