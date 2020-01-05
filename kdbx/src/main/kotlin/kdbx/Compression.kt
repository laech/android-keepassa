package kdbx

internal enum class Compression {

    // The ordinal of each value is also their corresponding ID
    NONE,
    GZIP;

    companion object {
        private val values = values()

        internal fun from(id: Int) = values.getOrNull(id)
            ?: throw IllegalArgumentException(id.toString())
    }
}
