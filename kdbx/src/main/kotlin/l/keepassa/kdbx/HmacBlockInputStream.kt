package l.keepassa.kdbx

import java.io.DataInput
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder.LITTLE_ENDIAN
import kotlin.math.min

internal class HmacBlockInputStream<T>(
    private val input: T,
    private val key: ByteArray
) : InputStream()
        where T : DataInput,
              T : InputStream {

    private var index: Long = 0
    private var buffer = ByteBuffer.allocate(0)

    override fun read(): Int {
        readNextBlockIfNecessary()
        if (!buffer.hasRemaining()) {
            return -1
        }
        return buffer.get().toInt().and(0xff)
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        readNextBlockIfNecessary()
        if (!buffer.hasRemaining()) {
            return -1
        }

        val minLen = min(len, buffer.remaining())
        buffer.get(b, off, minLen)
        return minLen
    }

    private fun readNextBlockIfNecessary() {
        if (buffer.hasRemaining()) {
            return
        }

        val blockMacExpected = input.readFully(32)
        val blockSize = input.readInt()
        val block = input.readFully(blockSize)

        val blockIndexBytes = index.encode(LITTLE_ENDIAN)
        val blockKey = sha512(blockIndexBytes, key)
        val blockMacActual = hmacSha256(blockKey).run {
            update(blockIndexBytes)
            update(blockSize.encode(LITTLE_ENDIAN))
            update(block)
            doFinal()
        }

        if (!blockMacExpected.contentEquals(blockMacActual)) {
            throw IOException("MAC mismatch.")
        }

        buffer = ByteBuffer.wrap(block)
        index++
    }
}
