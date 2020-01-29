package l.keepassa.kdbx

internal sealed class Binary {
    abstract val value: ByteString

    data class Protected(override val value: ByteString) : Binary()
    data class Plain(override val value: ByteString) : Binary()
}
