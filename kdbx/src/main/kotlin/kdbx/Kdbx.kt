package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.BIG_ENDIAN
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel
import java.util.*

private const val SIGNATURE_1: Int = -1700603645 // 0x9AA2D903
private const val SIGNATURE_2: Int = -1253311641 // 0xB54BFB67
private const val VERSION_4: Int = 0x00040000

private val ciphers = Cipher.values()
private val headers = Header.values()
private val compressions = Compression.values()

private enum class Header {
    // The ordinal of each value is also their corresponding ID
    /*  0 */ END_OF_HEADER,
    /*  1 */ COMMENT,
    /*  2 */ CIPHER_ID,
    /*  3 */ COMPRESSION_FLAGS,
    /*  4 */ MASTER_SEED,
    /*  5 */ TRANSFORM_SEED,
    /*  6 */ TRANSFORM_ROUNDS,
    /*  7 */ ENCRYPTION_IV,
    /*  8 */ PROTECTED_STREAM_KEY,
    /*  9 */ STREAM_START_BYTES,
    /* 10 */ INNER_RANDOM_STREAM_ID,
    /* 11 */ KDF_PARAMETERS,
    /* 12 */ PUBLIC_CUSTOM_DATA,
}

internal enum class Compression {
    // The ordinal of each value is also their corresponding ID
    /* 0 */ NONE,
    /* 1 */ GZIP,
}

internal enum class Cipher(val uuid: UUID) {
    AES128(UUID.fromString("61ab05a1-9464-41c3-8d74-3a563df8dd35")),
    AES256(UUID.fromString("31c1f2e6-bf71-4350-be58-05216afc5aff")),
    TWOFISH(UUID.fromString("ad68f29f-576f-4bb9-a36a-d47af965346c")),
    CHACHA20(UUID.fromString("d6038a2b-8b6f-4cb5-a524-339a31dbb59a")),
}

internal class ByteString private constructor(
    private val array: ByteArray
) {
    constructor(buf: ByteBuffer) : this(
        ByteArray(buf.remaining()).apply { buf.get(this) }
    )

    override fun toString() = Base64.getEncoder().encodeToString(array)
    override fun hashCode() = array.contentHashCode()
    override fun equals(other: Any?) =
        other is ByteString && array.contentEquals(other.array)
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
        if (id < 0 || id >= headers.size) {
            throw IllegalArgumentException()
        }

        val header = headers[java.lang.Byte.toUnsignedInt(id)]
        val length = readInt()
        val buffer = ByteBuffer.allocate(length).order(LITTLE_ENDIAN)
        if (input.read(buffer) != buffer.capacity()) {
            throw IllegalArgumentException()
        }

        buffer.flip()

        when (header) {
            Header.COMMENT -> return true
            Header.END_OF_HEADER -> return false
            Header.CIPHER_ID -> setCipher(buffer)
            Header.COMPRESSION_FLAGS -> setCompression(buffer)
            Header.MASTER_SEED -> setMasterSeed(buffer)
            Header.ENCRYPTION_IV -> setEncryptionIv(buffer)
            Header.KDF_PARAMETERS -> return true // TODO
            Header.PUBLIC_CUSTOM_DATA -> return true // TODO
            Header.PROTECTED_STREAM_KEY,
            Header.TRANSFORM_ROUNDS,
            Header.TRANSFORM_SEED,
            Header.STREAM_START_BYTES,
            Header.INNER_RANDOM_STREAM_ID -> throw IllegalArgumentException()
        }
        return true
    }

    private fun setCipher(buffer: ByteBuffer) {
        if (buffer.remaining() != 16) {
            throw IllegalArgumentException()
        }
        val uuid = buffer.order(BIG_ENDIAN).run {
            UUID(buffer.long, buffer.long)
        }
        cipher = ciphers.find { it.uuid == uuid }
            ?: throw IllegalArgumentException()
    }

    private fun setCompression(buffer: ByteBuffer) {
        if (buffer.remaining() != 4) {
            throw IllegalArgumentException()
        }
        val value = buffer.int
        if (value < 0 || value >= compressions.size) {
            throw IllegalArgumentException()
        }
        compression = compressions[value]
    }

    private fun setMasterSeed(buffer: ByteBuffer) {
        if (buffer.remaining() != 32) {
            throw IllegalArgumentException()
        }
        masterSeed = ByteString(buffer)
    }

    private fun setEncryptionIv(buffer: ByteBuffer) {
        encryptionIv = ByteString(buffer)
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
