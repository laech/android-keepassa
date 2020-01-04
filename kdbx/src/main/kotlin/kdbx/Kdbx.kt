package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.BIG_ENDIAN
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel
import java.util.*

private const val SIGNATURE_1: Int = -1700603645 // 0x9AA2D903
private const val SIGNATURE_2: Int = -1253311641 // 0xB54BFB67
private const val VERSION_4: Int = 0x00040000

private enum class Header {
    END_OF_HEADER,
    COMMENT,
    CIPHER_ID,
    COMPRESSION_FLAGS,
    MASTER_SEED,
    TRANSFORM_SEED,
    TRANSFORM_ROUNDS,
    ENCRYPTION_IV,
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

    private var cipher: Cipher? = null
    private var compression: Compression? = null
    private var masterSeed: ByteString? = null
    private var encryptionIv: ByteString? = null

    internal fun readSignature1(): Int = readExpectingInt(SIGNATURE_1)
    internal fun readSignature2(): Int = readExpectingInt(SIGNATURE_2)
    internal fun readVersion(): Int = readExpectingInt(VERSION_4)
    internal fun readHeaders(): Kdbx.Headers {
        while (readHeader()) {
        }
        return Kdbx.Headers(cipher, compression, masterSeed, encryptionIv)
    }

    private fun readHeader(): Boolean {
        val id = readByte()
        val header = Header.fromId(id)
        val length = readInt()
        val buffer = ByteBuffer.allocate(length).order(LITTLE_ENDIAN)
        if (input.read(buffer) != buffer.capacity()) {
            throw IllegalArgumentException()
        }

        buffer.flip()

        when (header) {
            Header.COMMENT -> return true
            Header.END_OF_HEADER -> return false
            Header.CIPHER_ID -> cipher = Cipher.fromUuidBuffer(buffer)
            Header.MASTER_SEED -> masterSeed = ByteString.fromBuffer(buffer, 32)
            Header.ENCRYPTION_IV -> encryptionIv = ByteString.fromBuffer(buffer)
            Header.COMPRESSION_FLAGS -> compression = Compression.fromIdBuffer(buffer)
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

    private fun readExpectingInt(expected: Int): Int {
        val actual = readInt()
        if (actual != expected) {
            throw IllegalArgumentException()
        }
        return actual
    }

    private fun readByte(): Byte {
        val buffer = ByteBuffer.allocate(1).order(LITTLE_ENDIAN)
        input.read(buffer)
        buffer.flip()
        return buffer.get()
    }

    private fun readInt(): Int {
        val buffer = ByteBuffer.allocate(4).order(LITTLE_ENDIAN)
        input.read(buffer)
        buffer.flip()
        return buffer.int
    }
}

internal data class Kdbx(
    val signature1: Int,
    val signature2: Int,
    val version: Int,
    val headers: Headers
) {
    internal data class Headers(
        val cipher: Cipher?,
        val compression: Compression?,
        val masterSeed: ByteString?,
        var encryptionIv: ByteString?
    )
}

internal fun kdbxRead(input: ReadableByteChannel): Kdbx {
    val reader = KdbxReader(input)
    val signature1 = reader.readSignature1()
    val signature2 = reader.readSignature2()
    val version = reader.readVersion()
    val headers = reader.readHeaders()
    return Kdbx(signature1, signature2, version, headers)
}
