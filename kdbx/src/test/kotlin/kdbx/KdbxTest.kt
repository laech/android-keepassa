package kdbx

import com.google.common.collect.ImmutableList
import com.google.common.collect.ImmutableMap
import com.kosprov.jargon2.api.Jargon2
import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.text.Charsets.UTF_8

class KdbxTest {

    @Test
    fun readsDatabase() {
        KdbxTest::class.java.getResourceAsStream("test.kdbx").use {
            val passwordHash = MessageDigest.getInstance("SHA-256")
                .digest("test".toByteArray(UTF_8))
            assertEquals(
                Kdbx(
                    signature1 = 0x9aa2d903.toInt(),
                    signature2 = 0xb54bfb67.toInt(),
                    version = 0x00040000,
                    headers = Headers(
                        compression = Compression.GZIP,
                        cipher = Cipher.AES,
                        masterSeed = ByteString.from(ByteBuffer.allocate(0)),
                        encryptionIv = ByteString.from(ByteBuffer.allocate(0)),
                        kdf = Kdf.Argon2(
                            Jargon2.Version.V13,
                            ByteString.from(ByteBuffer.allocate(8)),
                            65536,
                            10,
                            2
                        ),
                        publicCustomData = ImmutableMap.of()
                    ),
                    innerHeaders =
                    InnerHeaders(
                        innerRandomStreamKey = ByteString.from(
                            ByteBuffer.allocate(
                                0
                            )
                        ),
                        binaries = ImmutableList.of()
                    ),
                    content = Node("", ImmutableList.of(), Text(""))
                ),
                parseKdbx(it, passwordHash, null)
            )
        }
    }
}
