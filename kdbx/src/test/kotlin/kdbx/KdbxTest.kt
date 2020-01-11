package kdbx

import com.kosprov.jargon2.api.Jargon2
import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.text.Charsets.UTF_8

class KdbxTest {

    @Test
    fun readsDatabase() {
        val buffer =
            ByteBuffer.wrap(KdbxTest::class.java.getResourceAsStream("test.kdbx").use {
                it.readAllBytes()
            })
        val passwordHash = MessageDigest.getInstance("SHA-256")
            .digest("test".toByteArray(UTF_8))
        val db = Kdbx.read(buffer, passwordHash, null)
        assertEquals(0x9aa2d903, Integer.toUnsignedLong(db.signature1))
        assertEquals(0xb54bfb67, Integer.toUnsignedLong(db.signature2))
        assertEquals(0x00040000, db.version)
        assertEquals(
            Headers(
                compression = Compression.GZIP,
                cipher = Cipher.AES256,
                masterSeed = ByteString.from(ByteBuffer.allocate(0)),
                encryptionIv = ByteString.from(ByteBuffer.allocate(0)),
                kdf = Kdf.Argon2(
                    Jargon2.Version.V13,
                    ByteString.from(ByteBuffer.allocate(8)),
                    65536,
                    10,
                    2
                ),
                publicCustomData = null
            ),
            db.headers
        )
    }
}
