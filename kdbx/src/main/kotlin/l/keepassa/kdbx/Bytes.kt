package l.keepassa.kdbx

import java.io.DataInput
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal fun ByteArray.toHexString(): String =
    joinToString("") { "%02x".format(it) }

internal fun Int.encode(order: ByteOrder): ByteArray = ByteBuffer
    .allocate(Int.SIZE_BYTES)
    .order(order)
    .putInt(this)
    .array()

internal fun Long.encode(order: ByteOrder): ByteArray = ByteBuffer
    .allocate(Long.SIZE_BYTES)
    .order(order)
    .putLong(this)
    .array()

internal fun ByteBuffer.getByteArray(size: Int = remaining()): ByteArray =
    ByteArray(size).also { get(it) }

internal fun DataInput.readFully(size: Int): ByteArray =
    ByteArray(size).also(::readFully)
