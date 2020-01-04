package kdbx

import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.channels.Channels

class KdbxTest {

    @Test
    fun readsDatabase() {

        KdbxTest::class.java.getResourceAsStream("test.kdbx").use {
            val db = kdbxRead(Channels.newChannel(it))
            assertEquals("9aa2d903", Integer.toHexString(db.signature1))
            assertEquals("b54bfb67", Integer.toHexString(db.signature2))
            assertEquals("40000", Integer.toHexString(db.version))
            assertEquals(
                Kdbx.Headers(
                    cipher = Cipher.AES256,
                    compression = Compression.GZIP,
                    encryptionIv = null,
                    masterSeed = null
                ),
                db.headers
            )
        }
    }
}
