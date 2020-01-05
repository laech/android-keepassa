package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.nio.channels.ReadableByteChannel
import kotlin.experimental.and

internal data class Headers(
    val compression: Compression?,
    val cipher: Cipher?,
    val masterSeed: ByteString?,
    var encryptionIv: ByteString?,
    val kdfParameters: Map<String, Any>?,
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
            input: ReadableByteChannel,
            builder: VariantMap.Builder
        ): Boolean {

            val header = Header.of(input.read8())
            if (header == Header.EndOfHeader) {
                return false
            }

            val length = input.read32le()
            val valueBuffer = ByteBuffer.allocate(length)
                .order(LITTLE_ENDIAN)

            input.readFully(valueBuffer)
            valueBuffer.flip()
            builder[header] = header.decode(
                valueBuffer
                    .asReadOnlyBuffer()
                    .order(valueBuffer.order())
            )
            return true
        }

        private fun from(map: VariantMap) = Headers(
            compression = map[Header.Compression],
            cipher = map[Header.Cipher],
            masterSeed = map[Header.MasterSeed],
            encryptionIv = map[Header.EncryptionIv],
            kdfParameters = map[Header.KdfParameters],
            publicCustomData = map[Header.PublicCustomData]
        )
    }
}

internal sealed class Header<out T>(
    private val id: Byte,
    private val decoder: (ByteBuffer) -> T = {
        throw UnsupportedOperationException()
    }
) : VariantMap.Key<T> {

    fun decode(buffer: ByteBuffer): T = decoder(buffer)

    override fun toString(): String = javaClass.simpleName

    object EndOfHeader : Header<Unit>(0)
    object Comment : Header<Unit>(1)

    object Cipher :
        Header<kdbx.Cipher>(2, kdbx.Cipher.Companion::fromUuidBuffer)

    object Compression :
        Header<kdbx.Compression>(3, kdbx.Compression.Companion::fromIdBuffer)

    object MasterSeed : Header<ByteString>(4, {
        ByteString.fromBuffer(it, 32)
    })

    object EncryptionIv : Header<ByteString>(7, {
        ByteString.fromBuffer(it)
    })

    object KdfParameters : Header<Map<String, Any>>(11, ::readVariants)

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
    val valueBuffer = ByteBuffer.wrap(valueArray)
    input.get(valueArray)

    variants[name] = when (type) {
        Variant.BOOL -> valueBuffer.get() != 0.toByte()
        Variant.INT32,
        Variant.UINT32 -> valueBuffer.int
        Variant.INT64,
        Variant.UINT64 -> valueBuffer.long
        Variant.STRING -> String(valueArray, Charsets.UTF_8)
        Variant.BYTE_ARRAY -> ByteString.fromBuffer(valueBuffer)
        Variant.End -> return false
    }

    return true
}
