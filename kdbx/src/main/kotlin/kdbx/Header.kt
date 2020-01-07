package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.BIG_ENDIAN
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel
import java.util.*
import kotlin.collections.HashMap
import kotlin.experimental.and

internal data class Headers(
    val compression: Compression?,
    val cipher: Cipher,
    val masterSeed: ByteString,
    var encryptionIv: ByteString,
    val kdfParameters: Kdf?,
    val publicCustomData: Map<String, Any>?
) {
    companion object {

        fun read(input: ReadableByteChannel): Headers {
            val map = VariantMap.Builder()
            while (readSingle(input, map)) {
                // continue
            }
            return from(map.build())
        }

        private fun readSingle(
            channel: ReadableByteChannel,
            builder: VariantMap.Builder
        ): Boolean {

            val header = Header.of(channel.read8())
            if (header == Header.EndOfHeader) {
                return false
            }

            val length = channel.read32le()
            builder[header] = header.read(channel, length)
            return true
        }

        private fun from(map: VariantMap) = Headers(
            compression = map[Header.Compression],
            cipher = map.require(Header.Cipher),
            masterSeed = map.require(Header.MasterSeed),
            encryptionIv = map.require(Header.EncryptionIv),
            kdfParameters = map[Header.KdfParameters],
            publicCustomData = map[Header.PublicCustomData]
        )
    }
}

internal sealed class Header<out T>(
    private val id: Byte,
    private val reader: (ReadableByteChannel, Int) -> T
) : VariantMap.Key<T> {

    fun read(channel: ReadableByteChannel, length: Int): T =
        reader(channel, length)

    override fun toString(): String = javaClass.simpleName

    object EndOfHeader : Header<Unit>(0, { channel, length ->
        channel.readFully(length, LITTLE_ENDIAN)
    })

    object Comment : Header<Unit>(1, { channel, length ->
        channel.readFully(length, LITTLE_ENDIAN)
    })

    object Cipher : Header<kdbx.Cipher>(2, { channel, length ->
        if (length != 16) {
            throw IllegalArgumentException(length.toString())
        }
        val buffer = channel.readFully(length, BIG_ENDIAN)
        kdbx.Cipher.from(UUID(buffer.long, buffer.long))
    })

    object Compression : Header<kdbx.Compression>(3, { channel, length ->
        if (length != 4) {
            throw IllegalArgumentException(length.toString())
        }
        val buffer = channel.readFully(length, LITTLE_ENDIAN)
        kdbx.Compression.from(buffer.int)
    })

    object MasterSeed : Header<ByteString>(4, { channel, length ->
        if (length != 32) {
            throw IllegalArgumentException(length.toString())
        }
        val buffer = channel.readFully(length, LITTLE_ENDIAN)
        ByteString.from(buffer)
    })

    object EncryptionIv : Header<ByteString>(7, { channel, length ->
        val buffer = channel.readFully(length, LITTLE_ENDIAN)
        ByteString.from(buffer)
    })

    object KdfParameters : Header<Kdf>(11, { channel, length ->
        Kdf.from(readVariants(channel, length))
    })

    object PublicCustomData : Header<Map<String, Any>>(12, ::readVariants)

    companion object {

        private val headers = listOf(
            EndOfHeader,
            Comment,
            Cipher,
            Compression,
            MasterSeed,
            EncryptionIv,
            KdfParameters,
            PublicCustomData
        ).associateBy(Header<*>::id)

        fun of(id: Byte): Header<Any> = headers.getOrElse(id) {
            throw IllegalArgumentException("Unsupported header type $id")
        }
    }
}

private fun readVariants(
    channel: ReadableByteChannel,
    length: Int
): Map<String, Any> {
    val buffer = channel.readFully(length, LITTLE_ENDIAN)
    val version = buffer.short.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
    val maxVersion =
        Kdbx.VARIANT_VERSION.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
    if (version > maxVersion) {
        throw IllegalArgumentException(
            "Unsupported version 0x${Integer.toHexString(
                java.lang.Short.toUnsignedInt(version)
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
        String(this, Charsets.UTF_8)
    }

    val valueArray = ByteArray(input.int)
    val valueBuffer = ByteBuffer.wrap(valueArray).order(input.order())
    input.get(valueArray)

    variants[name] = when (type) {
        Variant.BOOL -> valueBuffer.get() != 0.toByte()
        Variant.INT32,
        Variant.UINT32 -> valueBuffer.int
        Variant.INT64,
        Variant.UINT64 -> valueBuffer.long
        Variant.STRING -> String(valueArray, Charsets.UTF_8)
        Variant.BYTE_ARRAY -> ByteString.from(valueBuffer)
        Variant.End -> return false
    }

    return true
}
