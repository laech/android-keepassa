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
        fun from(buf: ByteBuffer) =
            ByteString(ByteArray(buf.remaining()).apply { buf.get(this) })
    }
}
