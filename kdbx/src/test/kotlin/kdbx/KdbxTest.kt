package kdbx

import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.channels.Channels

class KdbxTest {

    @Test
    fun readsDatabase() {

        KdbxTest::class.java.getResourceAsStream("test.kdbx").use {
            val db = Kdbx.read(Channels.newChannel(it))
            assertEquals(0x9aa2d903, Integer.toUnsignedLong(db.signature1))
            assertEquals(0xb54bfb67, Integer.toUnsignedLong(db.signature2))
            assertEquals(0x00040000, db.version)
            assertEquals(
                Kdbx.Headers(
                    compression = Compression.GZIP,
                    cipher = Cipher.AES256,
                    seed = null,
                    iv = null
                ),
                db.headers
            )
        }
    }
}
