package kdbx

import java.io.EOFException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel

internal fun ReadableByteChannel.readFully(
    length: Int,
    order: ByteOrder
): ByteBuffer {
    val buffer = ByteBuffer.allocate(length)
    readFully(buffer)
    return buffer.flip().order(order)
}

internal fun ReadableByteChannel.readFully(buffer: ByteBuffer) {
    while (buffer.hasRemaining()) {
        if (read(buffer) == -1) {
            throw EOFException()
        }
    }
}

internal fun ReadableByteChannel.read8(): Byte {
    val buffer = ByteBuffer.allocate(1)
    readFully(buffer)
    buffer.flip()
    return buffer.get()
}

internal fun ReadableByteChannel.read32le(
    validate: ((Int) -> Boolean)? = null
): Int {
    val buffer = ByteBuffer.allocate(4).order(LITTLE_ENDIAN)
    readFully(buffer)
    buffer.flip()
    val value = buffer.int
    if (validate != null && !validate(value)) {
        throw IllegalArgumentException(Integer.toHexString(value))
    }
    return value
}
