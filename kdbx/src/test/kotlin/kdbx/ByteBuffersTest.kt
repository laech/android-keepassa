package kdbx

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import kotlin.text.Charsets.UTF_8

class ByteBuffersTest {

    @Test
    fun `getByteBuffer splits buffer correctly`() {
        val tail = ByteBuffer.wrap(" helloworld".toByteArray(UTF_8)).position(1)
        val init = tail.getByteBuffer(5)
        assertEquals("hello", UTF_8.decode(init).toString())
        assertEquals("world", UTF_8.decode(tail).toString())
    }

    @Test
    fun `getByteArray returns copy of content`() {
        val a = "hello".toByteArray()
        val b = ByteBuffer.wrap(a).getByteArray()
        assertArrayEquals(a, b)
        assertNotSame(a, b)
    }
}
