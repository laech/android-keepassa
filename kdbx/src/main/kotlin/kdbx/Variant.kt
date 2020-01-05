package kdbx

internal enum class Variant(private val id: Byte) {
    End(0),
    UINT32(0x04),
    UINT64(0x05),
    BOOL(0x08),
    INT32(0x0c),
    INT64(0x0d),
    STRING(0x18),
    BYTE_ARRAY(0x42);

    companion object {
        private val values = values().toList().sortedBy(Variant::id)

        fun fromId(id: Byte): Variant = values.find { it.id == id }
            ?: throw IllegalArgumentException(id.toString())
    }
}
