package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.BIG_ENDIAN
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel
import java.util.*

private enum class Header {
    END,
    COMMENT,
    CIPHER,
    COMPRESSION,
    SEED,
    TRANSFORM_SEED,
    TRANSFORM_ROUNDS,
    IV,
    PROTECTED_STREAM_KEY,
    STREAM_START_BYTES,
    INNER_RANDOM_STREAM_ID,
    KDF_PARAMETERS,
    PUBLIC_CUSTOM_DATA;

    companion object {
        private val values = values()

        // The ordinal of each value is also their corresponding ID
        fun fromId(id: Byte): Header = values.getOrNull(id.toInt())
            ?: throw IllegalArgumentException(id.toString())
    }
}

internal enum class Compression {
    NONE,
    GZIP;

    companion object {
        private val values = values()

        // The ordinal of each value is also their corresponding ID
        private fun fromId(id: Int) = values.getOrNull(id)
            ?: throw IllegalArgumentException(id.toString())

        fun fromIdBuffer(buffer: ByteBuffer): Compression = when {
            buffer.remaining() != 4 -> throw IllegalArgumentException()
            else -> fromId(buffer.int)
        }
    }
}

internal enum class Cipher(uuidStr: String) {
    AES128("61ab05a1-9464-41c3-8d74-3a563df8dd35"),
    AES256("31c1f2e6-bf71-4350-be58-05216afc5aff"),
    TWOFISH("ad68f29f-576f-4bb9-a36a-d47af965346c"),
    CHACHA20("d6038a2b-8b6f-4cb5-a524-339a31dbb59a");

    val uuid = UUID.fromString(uuidStr)

    companion object {
        private val values = values()

        private fun fromUuid(uuid: UUID) = values.find { it.uuid == uuid }
            ?: throw IllegalArgumentException(uuid.toString())

        fun fromUuidBuffer(buffer: ByteBuffer): Cipher = when {
            buffer.remaining() != 16 -> throw IllegalArgumentException()
            else -> fromUuid(buffer.order(BIG_ENDIAN).run {
                UUID(buffer.long, buffer.long)
            })
        }
    }
}

private class KdbxReader(private val input: ReadableByteChannel) {

    private var compression: Compression? = null
    private var cipher: Cipher? = null
    private var seed: ByteString? = null
    private var iv: ByteString? = null

    internal fun readSignature1(): Int = read32 { it == Kdbx.SIGNATURE_1 }
    internal fun readSignature2(): Int = read32 { it == Kdbx.SIGNATURE_2 }

    internal fun readVersion(): Int = read32 {
        it.and(Kdbx.FILE_VERSION_MAJOR_MASK) == Kdbx.FILE_VERSION_4
    }

    internal fun readHeaders(): Kdbx.Headers {
        while (readHeader()) {
            // continue
        }
        return Kdbx.Headers(compression, cipher, seed, iv)
    }

    private fun readHeader(): Boolean {
        val id = read8()
        val header = Header.fromId(id)
        val length = read32()
        val buffer = ByteBuffer.allocate(length).order(LITTLE_ENDIAN)
        if (input.read(buffer) != buffer.capacity()) {
            throw IllegalArgumentException()
        }

        buffer.flip()

        when (header) {
            Header.END -> return false
            Header.COMMENT -> return true
            Header.COMPRESSION -> compression = Compression.fromIdBuffer(buffer)
            Header.CIPHER -> cipher = Cipher.fromUuidBuffer(buffer)
            Header.SEED -> seed = ByteString.fromBuffer(buffer, 32)
            Header.IV -> iv = ByteString.fromBuffer(buffer)
            Header.KDF_PARAMETERS -> return true // TODO
            Header.PUBLIC_CUSTOM_DATA -> return true // TODO
            Header.PROTECTED_STREAM_KEY,
            Header.TRANSFORM_ROUNDS,
            Header.TRANSFORM_SEED,
            Header.STREAM_START_BYTES,
            Header.INNER_RANDOM_STREAM_ID ->
                throw IllegalArgumentException(header.toString())
        }
        return true
    }

    private fun read8(): Byte {
        val buffer = ByteBuffer.allocate(1).order(LITTLE_ENDIAN)
        input.read(buffer)
        buffer.flip()
        return buffer.get()
    }

    private fun read32(validate: ((Int) -> Boolean)? = null): Int {
        val buffer = ByteBuffer.allocate(4).order(LITTLE_ENDIAN)
        input.read(buffer)
        buffer.flip()
        val value = buffer.int
        if (validate != null && !validate(value)) {
            throw IllegalArgumentException(Integer.toHexString(value.toInt()))
        }
        return value
    }
}

internal data class Kdbx(
    val signature1: Int,
    val signature2: Int,
    val version: Int,
    val headers: Headers
) {
    internal data class Headers(
        val compression: Compression?,
        val cipher: Cipher?,
        val seed: ByteString?,
        var iv: ByteString?
    )

    companion object {
        internal const val SIGNATURE_1: Int = 0x9aa2d903.toInt()
        internal const val SIGNATURE_2: Int = 0xb54bfb67.toInt()
        internal const val FILE_VERSION_MAJOR_MASK: Int = 0xffff0000.toInt()
        internal const val FILE_VERSION_4: Int = 0x00040000

        internal fun read(input: ReadableByteChannel): Kdbx {
            val reader = KdbxReader(input)
            val signature1 = reader.readSignature1()
            val signature2 = reader.readSignature2()
            val version = reader.readVersion()
            val headers = reader.readHeaders()
            return Kdbx(
                signature1,
                signature2,
                version,
                headers
            )
        }
    }
}
