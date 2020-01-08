package kdbx

import java.nio.ByteBuffer

internal fun ByteBuffer.getAll(length: Int): ByteBuffer {
    val result = slice().limit(length).slice().order(order())
    position(position() + length)
    return result
}
