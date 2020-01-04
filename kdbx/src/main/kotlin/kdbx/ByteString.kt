package kdbx

import java.nio.ByteBuffer

internal class ByteString private constructor(
    private val array: ByteArray
) {
    override fun toString(): String =
        array.joinToString("") { "%02x".format(it) }

    override fun hashCode() = array.contentHashCode()

    override fun equals(other: Any?) =
        other is ByteString && array.contentEquals(other.array)

    companion object {
        fun fromBuffer(buf: ByteBuffer, expectedSize: Int = buf.remaining()) = when {
            expectedSize != buf.remaining() ->
                throw IllegalArgumentException(
                    "buffer.remaining=${buf.remaining()}, expectedSize=$expectedSize"
                )
            else -> ByteString(ByteArray(buf.remaining()).apply { buf.get(this) })
        }
    }
}
