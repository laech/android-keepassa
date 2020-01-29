package l.keepassa.kdbx

import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.util.*

internal class BufferingInputStream(input: InputStream) :
    BufferedInputStream(input) {

    fun drainFromMark(): ByteArray {
        if (markpos < 0) {
            throw IOException("Mark not set")
        }
        val bytes = Arrays.copyOfRange(buf, markpos, pos)
        reset()
        skip(bytes.size.toLong())
        return bytes
    }
}
