package kdbx

import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.security.MessageDigest
import kotlin.text.Charsets.UTF_8

class KdbxTest {

    @Test
    fun readsDatabase() {
        KdbxTest::class.java.getResourceAsStream("test.kdbx").use {
            val key = MessageDigest.getInstance("SHA-256")
                .digest("test".toByteArray(UTF_8))
            val db = Kdbx.read(Channels.newChannel(it), key)
            assertEquals(0x9aa2d903, Integer.toUnsignedLong(db.signature1))
            assertEquals(0xb54bfb67, Integer.toUnsignedLong(db.signature2))
            assertEquals(0x00040000, db.version)
            assertEquals(
                Headers(
                    compression = Compression.GZIP,
                    cipher = Cipher.AES256,
                    masterSeed = ByteString.from(ByteBuffer.allocate(0)),
                    encryptionIv = ByteString.from(ByteBuffer.allocate(0)),
                    kdfParameters = null,
                    publicCustomData = null
                ),
                db.headers
            )
        }
    }
}
