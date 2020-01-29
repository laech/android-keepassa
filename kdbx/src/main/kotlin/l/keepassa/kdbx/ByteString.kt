package l.keepassa.kdbx

import java.nio.ByteBuffer

internal class ByteString private constructor(
    private val array: ByteArray
) {
    val size: Int get() = array.size

    constructor(buffer: ByteBuffer) : this(buffer.getByteArray())

    override fun toString(): String =
        array.joinToString("") { "%02x".format(it) }

    override fun hashCode() = array.contentHashCode()

    override fun equals(other: Any?) =
        other is ByteString && array.contentEquals(other.array)

    fun toReadonlyByteBuffer(): ByteBuffer =
        ByteBuffer.wrap(array).asReadOnlyBuffer()

    fun toByteArray(): ByteArray = array.clone()

    companion object {
        fun from(buf: ByteBuffer) =
            ByteString(ByteArray(buf.remaining()).apply { buf.get(this) })
    }
}
