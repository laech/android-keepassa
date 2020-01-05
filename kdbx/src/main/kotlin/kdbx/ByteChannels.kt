package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel

internal fun ReadableByteChannel.read8(): Byte {
    val buffer = ByteBuffer.allocate(1)
    read(buffer)
    buffer.flip()
    return buffer.get()
}

internal fun ReadableByteChannel.read32le(
    validate: ((Int) -> Boolean)? = null
): Int {
    val buffer = ByteBuffer.allocate(4).order(LITTLE_ENDIAN)
    read(buffer)
    buffer.flip()
    val value = buffer.int
    if (validate != null && !validate(value)) {
        throw IllegalArgumentException(Integer.toHexString(value))
    }
    return value
}
