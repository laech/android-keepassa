package l.keepassa.kdbx

import com.google.common.collect.ImmutableList
import com.google.common.collect.ImmutableMap
import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer
import org.signal.argon2.Version as Argon2Version

class KdbxTest {

    @Test
    fun readsDatabase() {
        KdbxTest::class.java.getResourceAsStream("test.kdbx").use {
            val kdbx = parseKdbx(it!!, "test", null)
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
                            Argon2Version.V13,
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
                kdbx
            )
        }
    }
}
