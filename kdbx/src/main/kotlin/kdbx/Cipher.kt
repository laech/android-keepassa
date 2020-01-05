package kdbx

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*

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
            else -> fromUuid(buffer.order(ByteOrder.BIG_ENDIAN).run {
                UUID(buffer.long, buffer.long)
            })
        }
    }
}
