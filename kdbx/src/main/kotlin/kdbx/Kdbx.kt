package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel
import kotlin.experimental.and
import kotlin.text.Charsets.UTF_8

private class KdbxReader {

    private var compression: Compression? = null
    private var cipher: Cipher? = null
    private var seed: ByteString? = null
    private var iv: ByteString? = null
    private var kdf: Map<String, Any>? = null
    private var publicCustomData: Map<String, Any>? = null

    internal fun readSignature1(input: ReadableByteChannel): Int =
        read32(input) { it == Kdbx.SIGNATURE_1 }

    internal fun readSignature2(input: ReadableByteChannel): Int =
        read32(input) { it == Kdbx.SIGNATURE_2 }

    internal fun readVersion(input: ReadableByteChannel): Int = read32(input) {
        it.and(Kdbx.FILE_VERSION_MAJOR_MASK) == Kdbx.FILE_VERSION_4
    }

    internal fun readHeaders(input: ReadableByteChannel): Kdbx.Headers {
        while (readHeader(input)) {
            // continue
        }
        return Kdbx.Headers(
            compression,
            cipher,
            seed,
            iv,
            kdf,
            publicCustomData
        )
    }

    private fun readHeader(input: ReadableByteChannel): Boolean {
        val id = read8(input)
        val header = Header.fromId(id)
        val length = read32(input)
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
            Header.KDF_PARAMETERS -> kdf = readVariants(buffer) // TODO
            Header.PUBLIC_CUSTOM_DATA -> publicCustomData = readVariants(buffer)
            Header.PROTECTED_STREAM_KEY,
            Header.TRANSFORM_ROUNDS,
            Header.TRANSFORM_SEED,
            Header.STREAM_START_BYTES,
            Header.INNER_RANDOM_STREAM_ID ->
                throw IllegalArgumentException(header.toString())
        }
        return true
    }

    private fun readVariants(buffer: ByteBuffer): Map<String, Any> {
        val version = buffer.short.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
        val maxVersion =
            Kdbx.VARIANT_VERSION.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
        if (version > maxVersion) {
            throw IllegalArgumentException(
                "Unsupported version 0x${Integer.toHexString(
                    java.lang.Short.toUnsignedInt(
                        version
                    )
                )}"
            )
        }

        val variants = HashMap<String, Any>()
        while (readVariant(buffer, variants)) {
            // continue
        }
        return variants
    }

    private fun readVariant(
        input: ByteBuffer,
        variants: MutableMap<String, Any>
    ): Boolean {
        val type = Variant.fromId(input.get())
        if (type == Variant.End) {
            return false
        }

        val name = ByteArray(input.int).run {
            input.get(this)
            String(this, UTF_8)
        }

        val valueArray = ByteArray(input.int)
        val valueBuffer = ByteBuffer.wrap(valueArray)
        input.get(valueArray);

        variants[name] = when (type) {
            Variant.BOOL -> valueBuffer.get() != 0.toByte()
            Variant.INT32,
            Variant.UINT32 -> valueBuffer.int
            Variant.INT64,
            Variant.UINT64 -> valueBuffer.long
            Variant.STRING -> String(valueArray, UTF_8)
            Variant.BYTE_ARRAY -> ByteString.fromBuffer(valueBuffer)
            Variant.End -> return false
        }

        return true
    }

    private fun read8(input: ReadableByteChannel): Byte {
        val buffer = ByteBuffer.allocate(1).order(LITTLE_ENDIAN)
        input.read(buffer)
        buffer.flip()
        return buffer.get()
    }

    private fun read32(
        input: ReadableByteChannel,
        validate: ((Int) -> Boolean)? = null
    ): Int {
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
        var iv: ByteString?,
        val kdf: Map<String, Any>?,
        val publicCustomData: Map<String, Any>?
    )

    companion object {
        internal const val SIGNATURE_1: Int = 0x9aa2d903.toInt()
        internal const val SIGNATURE_2: Int = 0xb54bfb67.toInt()
        internal const val FILE_VERSION_MAJOR_MASK: Int = 0xffff0000.toInt()
        internal const val FILE_VERSION_4: Int = 0x00040000
        internal const val VARIANT_VERSION_MAJOR_MASK: Short = 0xff00.toShort()
        internal const val VARIANT_VERSION: Short = 0x0100

        internal fun read(input: ReadableByteChannel): Kdbx {
            val reader = KdbxReader()
            val signature1 = reader.readSignature1(input)
            val signature2 = reader.readSignature2(input)
            val version = reader.readVersion(input)
            val headers = reader.readHeaders(input)
            return Kdbx(
                signature1,
                signature2,
                version,
                headers
            )
        }
    }
}
