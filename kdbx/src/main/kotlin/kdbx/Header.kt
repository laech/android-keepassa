package kdbx

internal enum class Header {

    // The ordinal of each value is also their corresponding ID
    END,
    COMMENT,
    CIPHER,
    COMPRESSION,
    SEED,
    TRANSFORM_SEED,
    TRANSFORM_ROUNDS,
    IV,
    PROTECTED_STREAM_KEY,
    STREAM_START_BYTES,
    INNER_RANDOM_STREAM_ID,
    KDF_PARAMETERS,
    PUBLIC_CUSTOM_DATA;

    companion object {
        private val values = values()

        fun fromId(id: Byte): Header = values.getOrNull(id.toInt())
            ?: throw IllegalArgumentException(id.toString())
    }
}
