package kdbx

import com.google.common.collect.ImmutableList
import com.google.common.collect.ImmutableMap
import com.google.common.io.LittleEndianDataInputStream
import java.io.DataInput
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.ByteOrder.BIG_ENDIAN
import java.nio.ByteOrder.LITTLE_ENDIAN
import java.util.*
import java.util.zip.GZIPInputStream
import kotlin.NoSuchElementException
import kotlin.experimental.and
import kotlin.text.Charsets.UTF_8

private typealias Parser<I, O> = (I) -> O

private fun <I, O> O.const(): Parser<I, O> = { this }

private fun <I, O, U> Parser<I, O>.map(mapper: (O) -> U): Parser<I, U> =
    { mapper(this(it)) }

private fun <I, O, U> Parser<I, O>.flatMap(mapper: (O) -> Parser<I, U>): Parser<I, U> =
    { mapper(this(it))(it) }

private fun <I, A, B> Parser<I, A>.pair(second: Parser<I, B>): Parser<I, Pair<A, B>> =
    { Pair(this(it), second(it)) }

private fun <I, A, B, C> Parser<I, Pair<A, B>>.flatMapSecond(mapper: (A, B) -> Parser<B, C>)
        : Parser<I, Pair<A, C>> =
    {
        val (a, b) = this(it)
        val c = mapper(a, b)(b)
        Pair(a, c)
    }

private fun <I, O> Parser<I, O>.repeat(): Parser<I, Sequence<O>> =
    { input -> generateSequence { this }.map { it(input) } }

private fun <I, O> Parser<I, O>.checkInput(check: (I) -> Unit): Parser<I, O> =
    {
        check(it)
        this(it)
    }

private fun <I, O> Parser<I, O>.checkOutput(check: (O) -> Unit): Parser<I, O> =
    { this(it).also(check) }


@Suppress("UNCHECKED_CAST")
private fun <T> unitParser(): Parser<T, Unit> = unitParser as Parser<T, Unit>

private val unitParser: Parser<Any, Unit> = {}


private typealias BufferParser<T> = Parser<ByteBuffer, T>

private val bufferGetInt: BufferParser<Int> = ByteBuffer::getInt
private val bufferGetByte: BufferParser<Byte> = ByteBuffer::get
private val bufferGetLong: BufferParser<Long> = ByteBuffer::getLong
private val bufferGetShort: BufferParser<Short> = ByteBuffer::getShort
private val bufferGetBoolean: BufferParser<Boolean> =
    bufferGetByte.map { it != 0.toByte() }

private fun bufferGetByteArray(size: Int): BufferParser<ByteArray> =
    { it.getByteArray(size) }

private fun bufferGetUtf8(size: Int): BufferParser<String> =
    bufferGetByteArray(size).map { String(it, UTF_8) }

private val bufferGetUtf8: BufferParser<String> =
    bufferGetInt.flatMap(::bufferGetUtf8)

private fun bufferGetByteBuffer(size: Int): BufferParser<ByteBuffer> = {
    val result = it.slice().limit(size).order(it.order())
    it.position(it.position() + size)
    result
}

private val bufferGetByteBuffer: BufferParser<ByteBuffer> =
    bufferGetInt.flatMap(::bufferGetByteBuffer)

private val bufferToInt: BufferParser<Int> = bufferGetInt.checkInput {
    if (it.remaining() != Int.SIZE_BYTES) {
        throw IllegalArgumentException("Invalid size of int: ${it.remaining()}")
    }
}

private val bufferToByteArray: BufferParser<ByteArray> = { it.getByteArray() }
private val bufferToByteString: BufferParser<ByteString> = ::ByteString
private val bufferToUtf8: BufferParser<String> =
    bufferToByteArray.map { String(it, UTF_8) }

private val bufferToUuid: BufferParser<UUID> = {
    if (it.remaining() != Long.SIZE_BYTES * 2) {
        throw IllegalArgumentException("Buffer with size ${it.remaining()}")
    }
    it.slice().order(BIG_ENDIAN).run {
        UUID(long, long)
    }
}


private typealias DataParser<T> = Parser<DataInput, T>

private val dataReadInt: DataParser<Int> = DataInput::readInt
private val dataReadByte: DataParser<Byte> = DataInput::readByte

private fun dataReadByteArray(size: Int): DataParser<ByteArray> =
    { it.readFully(size) }

private fun dataReadByteBuffer(
    order: ByteOrder,
    size: Int
): DataParser<ByteBuffer> =
    dataReadByteArray(size).map { ByteBuffer.wrap(it).order(order) }

private fun dataReadByteBuffer(order: ByteOrder): DataParser<ByteBuffer> =
    dataReadInt.flatMap { dataReadByteBuffer(order, it) }


private const val VARIANT_END: Byte = 0x0
private const val VARIANT_UINT32: Byte = 0x04
private const val VARIANT_UINT64: Byte = 0x05
private const val VARIANT_BOOL: Byte = 0x08
private const val VARIANT_INT32: Byte = 0x0c
private const val VARIANT_INT64: Byte = 0x0d
private const val VARIANT_STRING: Byte = 0x18
private const val VARIANT_BYTE_ARRAY: Byte = 0x42

private typealias VariantParser<T> = BufferParser<Pair<String, T>>

private fun <T> variantParser(valueParser: BufferParser<T>): VariantParser<T> =
    bufferGetUtf8.pair(bufferGetByteBuffer.map(valueParser))

private val variantEnd = Pair("", Unit)

private val variantParsers = mapOf(
    Pair(VARIANT_END, variantEnd.const()),
    Pair(VARIANT_UINT32, variantParser(bufferGetInt)),
    Pair(VARIANT_UINT64, variantParser(bufferGetLong)),
    Pair(VARIANT_BOOL, variantParser(bufferGetBoolean)),
    Pair(VARIANT_INT32, variantParser(bufferGetInt)),
    Pair(VARIANT_INT64, variantParser(bufferGetLong)),
    Pair(VARIANT_STRING, variantParser(bufferToUtf8)),
    Pair(VARIANT_BYTE_ARRAY, variantParser(bufferToByteString))
)

private val variantTypeParser: VariantParser<Any> =
    bufferGetByte.flatMap {
        variantParsers[it]
            ?: throw NoSuchElementException("Unknown variant type $it")
    }

private val variantsVersionParser: BufferParser<Unit> =
    bufferGetShort.map { version ->
        val major = version.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
        val max = Kdbx.VARIANT_VERSION.and(Kdbx.VARIANT_VERSION_MAJOR_MASK)
        if (major > max) {
            throw IllegalArgumentException(
                "Unsupported version 0x${Integer.toHexString(
                    java.lang.Short.toUnsignedInt(major)
                )}"
            )
        }
    }

private val variantsDataParser: BufferParser<ImmutableMap<String, Any>> =
    variantTypeParser.repeat().map { variants ->
        variants
            .takeWhile { it != variantEnd }
            .toMap()
            .let { ImmutableMap.copyOf(it) }
    }

private val variantsParser: BufferParser<ImmutableMap<String, Any>> =
    variantsVersionParser.flatMap { variantsDataParser }


private const val HEADER_END: Byte = 0x0
private const val HEADER_COMMENT: Byte = 0x1
private const val HEADER_CIPHER: Byte = 0x2
private const val HEADER_COMPRESSION: Byte = 0x3
private const val HEADER_MASTER_SEED: Byte = 0x4
private const val HEADER_ENCRYPTION_IV: Byte = 0x7
private const val HEADER_KDF: Byte = 0x0b
private const val HEADER_PUBLIC_CUSTOM_DATA: Byte = 0x0c

private val cipherParser: BufferParser<Cipher> =
    bufferToUuid.map(Cipher.Companion::from)

private val compressionParser: BufferParser<Compression> =
    bufferToInt.map(Compression.Companion::from)

private val masterSeedParser: BufferParser<ByteString> =
    bufferToByteString.checkInput {
        if (it.remaining() != 32) {
            throw IllegalArgumentException("Invalid seed size ${it.remaining()}")
        }
    }

private val kdfParser: BufferParser<Kdf> =
    variantsParser.map(Kdf.Companion::from)

private val headerParsers = mapOf(
    Pair(HEADER_END, unitParser()),
    Pair(HEADER_COMMENT, unitParser()),
    Pair(HEADER_CIPHER, cipherParser),
    Pair(HEADER_COMPRESSION, compressionParser),
    Pair(HEADER_MASTER_SEED, masterSeedParser),
    Pair(HEADER_ENCRYPTION_IV, bufferToByteString),
    Pair(HEADER_KDF, kdfParser),
    Pair(HEADER_PUBLIC_CUSTOM_DATA, variantsParser)
)

private val headerParser: DataParser<Pair<Byte, Any>> =
    dataReadByte
        .pair(dataReadByteBuffer(LITTLE_ENDIAN))
        .flatMapSecond { type, _ ->
            headerParsers[type]
                ?: throw IllegalArgumentException("Invalid header $type")
        }

private val headersParser: DataParser<Headers> =
    headerParser.repeat().map { headers ->
        headers.takeWhile { (type, _) -> type != HEADER_END }.toMap().run {
            Headers(
                kdf = getRequired(HEADER_KDF),
                cipher = getRequired(HEADER_CIPHER),
                masterSeed = getRequired(HEADER_MASTER_SEED),
                compression = getRequired(HEADER_COMPRESSION),
                encryptionIv = getRequired(HEADER_ENCRYPTION_IV),
                publicCustomData = getTyped(HEADER_PUBLIC_CUSTOM_DATA)
                    ?: ImmutableMap.of()
            )
        }
    }


private const val INNER_HEADER_END: Byte = 0x0
private const val INNER_HEADER_RANDOM_STREAM_ID: Byte = 0x1
private const val INNER_HEADER_RANDOM_STREAM_KEY: Byte = 0x2
private const val INNER_HEADER_BINARY: Byte = 0x3

private val binaryParser: BufferParser<Binary> =
    bufferGetBoolean.pair(bufferToByteString).map { (protected, value) ->
        if (protected) {
            Binary.Protected(value)
        } else {
            Binary.Plain(value)
        }
    }

private val innerRandomStreamIdParser = bufferToInt.map {
    if (it != 3) { // CharChar20
        throw IllegalArgumentException("Unknown inner random stream ID $it")
    }
}

private val innerHeaderParsers = mapOf(
    Pair(INNER_HEADER_END, unitParser()),
    Pair(INNER_HEADER_RANDOM_STREAM_ID, innerRandomStreamIdParser),
    Pair(INNER_HEADER_RANDOM_STREAM_KEY, bufferToByteString),
    Pair(INNER_HEADER_BINARY, binaryParser)
)

private val innerHeaderParser: DataParser<Pair<Byte, Any>> =
    dataReadByte
        .pair(dataReadByteBuffer(LITTLE_ENDIAN))
        .flatMapSecond { type, _ ->
            innerHeaderParsers[type]
                ?: throw IllegalArgumentException("Invalid inner header $type")
        }

private val innerHeadersParser: DataParser<InnerHeaders> =
    innerHeaderParser.repeat().map {
        var id = false
        var key: ByteString? = null
        val binaries = ImmutableList.builder<Binary>()

        it.takeWhile { (type, _) -> type != INNER_HEADER_END }
            .forEach { (type, value) ->
                when (type) {
                    INNER_HEADER_RANDOM_STREAM_ID -> id = true
                    INNER_HEADER_RANDOM_STREAM_KEY -> key = value as ByteString
                    INNER_HEADER_BINARY -> binaries.add(value as Binary)
                    else -> Unit
                }
            }

        if (!id) {
            throw NoSuchElementException("Inner random stream ID")
        }

        InnerHeaders(
            key ?: throw NoSuchElementException("Inner random stream key"),
            binaries.build()
        )
    }

private val signature1Parser: DataParser<Int> = { input ->
    when (val value = input.readInt()) {
        Kdbx.SIGNATURE_1 -> value
        else -> throw IllegalArgumentException("Unknown signature1: $value")
    }
}

private val signature2Parser: DataParser<Int> = { input ->
    when (val value = input.readInt()) {
        Kdbx.SIGNATURE_2 -> value
        else -> throw IllegalArgumentException("Unknown signature2: $value")
    }
}

private val versionParser: DataParser<Int> = dataReadInt.checkOutput {
    if (it.and(Kdbx.FILE_VERSION_MAJOR_MASK) != Kdbx.FILE_VERSION_4) {
        throw IllegalArgumentException("Unknown version: $it")
    }
}

private fun headerHashCheck(headerBytes: ByteArray): DataParser<Unit> =
    dataReadByteArray(32).map {
        val hash = sha256(headerBytes)
        if (!it.contentEquals(hash)) {
            throw IllegalArgumentException(
                "Header hash mismatch" +
                        ", stored ${it.toHexString()}" +
                        ", calculated ${hash.toHexString()}"
            )
        }
    }

private fun headerMacCheck(
    headers: ByteArray,
    macKey: ByteArray
): DataParser<Unit> = dataReadByteArray(32).map {
    val keyHash = sha512((-1L).encode(LITTLE_ENDIAN), macKey)
    val mac = hmacSha256(keyHash, headers)
    if (!it.contentEquals(mac)) {
        throw IllegalArgumentException(
            "Header MAC mismatch" +
                    ", stored ${it.toHexString()}" +
                    ", calculated ${mac.toHexString()}"
        )
    }
}

private fun databaseParser(
    headers: Headers,
    headerBytes: ByteArray,
    key: ByteArray
): Parser<LittleEndianDataInputStream, InnerHeaders> = { input ->

    val keyBuf = headers.masterSeed.toByteArray() +
            headers.kdf.transform(key) +
            byteArrayOf(1)
    val hmacKey = sha512(keyBuf)

    headerHashCheck(headerBytes)(input)
    headerMacCheck(headerBytes, hmacKey)(input)

    val hmacBlockStream = HmacBlockInputStream(input, hmacKey)
    val decryptedStream = headers.cipher.decrypt(
        hmacBlockStream,
        sha256(keyBuf.copyOfRange(0, 64)),
        headers.encryptionIv.toByteArray()
    )
    val dataStream =
        if (headers.compression == Compression.GZIP) {
            GZIPInputStream(decryptedStream)
        } else {
            decryptedStream
        }

    val innerHeaders =
        innerHeadersParser(LittleEndianDataInputStream(dataStream))

    dataStream.readAllBytes()

    innerHeaders
}

internal fun parseKdbx(
    input: InputStream,
    passwordHash: ByteArray?,
    keyFileHash: ByteArray?
): Kdbx {
    val buffer = BufferingInputStream(input)
    val data = LittleEndianDataInputStream(buffer)
    buffer.mark(Int.MAX_VALUE)

    val signature1 = signature1Parser(data)
    val signature2 = signature2Parser(data)
    val version = versionParser(data)
    val headers = headersParser(data)

    val headerBytes = buffer.drainFromMark()
    val key = sha256(
        *arrayOf(passwordHash, keyFileHash)
            .filterNotNull()
            .toTypedArray()
    )
    val innerHeaders = databaseParser(headers, headerBytes, key)(data)

    val kdbx = Kdbx(
        signature1,
        signature2,
        version,
        headers,
        innerHeaders
    )
    return kdbx
}
