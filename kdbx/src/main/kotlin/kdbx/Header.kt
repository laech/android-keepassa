package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.BIG_ENDIAN
import java.util.*
import kotlin.collections.HashMap
import kotlin.experimental.and

internal data class Headers(
    val compression: Compression?,
    val cipher: Cipher,
    val masterSeed: ByteString,
    var encryptionIv: ByteString,
    val kdf: Kdf,
    val publicCustomData: Map<String, Any>?
) {
    companion object {

        fun read(buffer: ByteBuffer): Headers {
            val map = VariantMap.Builder()
            while (readSingle(buffer, map)) {
                // continue
            }
            return from(map.build())
        }

        private fun readSingle(
            buffer: ByteBuffer,
            builder: VariantMap.Builder
        ): Boolean {

            val header = Header.of(buffer.get())
            val value = header.read(buffer.getByteBuffer(buffer.int))
            builder[header] = value
            return header != Header.EndOfHeader
        }

        private fun from(map: VariantMap) = Headers(
            compression = map[Header.Compression],
            cipher = map.require(Header.Cipher),
            masterSeed = map.require(Header.MasterSeed),
            encryptionIv = map.require(Header.EncryptionIv),
            kdf = map.require(Header.KdfParameters),
            publicCustomData = map[Header.PublicCustomData]
        )
    }
}

internal sealed class Header<out T>(
    private val id: Byte,
    private val reader: (ByteBuffer) -> T
) : VariantMap.Key<T> {

    fun read(buffer: ByteBuffer): T = reader(buffer)

    override fun toString(): String = javaClass.simpleName

    object EndOfHeader : Header<Unit>(0, {})

    object Comment : Header<Unit>(1, {})

    object Cipher : Header<kdbx.Cipher>(2, { buffer ->
        if (buffer.remaining() != Long.SIZE_BYTES * 2) {
            throw IllegalArgumentException("Buffer with size ${buffer.remaining()}")
        }
        buffer.slice().order(BIG_ENDIAN).run {
            kdbx.Cipher.from(UUID(long, long))
        }
    })

    object Compression : Header<kdbx.Compression>(3, { buffer ->
        if (buffer.remaining() != Int.SIZE_BYTES) {
            throw IllegalArgumentException("buffer with size ${buffer.remaining()}")
        }
        kdbx.Compression.from(buffer.int)
    })

    object MasterSeed : Header<ByteString>(4, { buffer ->
        if (buffer.remaining() != 32) {
            throw IllegalArgumentException("buffer with size ${buffer.remaining()}")
        }
        ByteString.from(buffer)
    })

    object EncryptionIv : Header<ByteString>(7, ByteString.Companion::from)

    object KdfParameters : Header<Kdf>(11, { buffer ->
        Kdf.from(readVariants(buffer))
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

private fun readVariants(buffer: ByteBuffer): Map<String, Any> {
    val version = buffer.short.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
    val maxVersion = Kdbx.VARIANT_VERSION.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
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
    buffer: ByteBuffer,
    variants: MutableMap<String, Any>
): Boolean {

    val type = Variant.fromId(buffer.get())
    if (type == Variant.End) {
        return false
    }

    val name = ByteArray(buffer.int).run {
        buffer.get(this)
        String(this, Charsets.UTF_8)
    }

    val valueArray = ByteArray(buffer.int)
    val valueBuffer = ByteBuffer.wrap(valueArray).order(buffer.order())
    buffer.get(valueArray)

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
