package kdbx

internal fun ByteArray.toHexString(): String =
    joinToString("") { "%02x".format(it) }
