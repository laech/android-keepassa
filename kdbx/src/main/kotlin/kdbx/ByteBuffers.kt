package kdbx

import java.nio.ByteBuffer

internal fun ByteBuffer.getByteBuffer(length: Int): ByteBuffer {
    val result = slice().limit(length).slice().order(order())
    position(position() + length)
    return result
}

internal fun ByteBuffer.getByteArray(length: Int = remaining()): ByteArray {
    val result = ByteArray(length)
    get(result)
    return result
}
