package kdbx

import com.google.common.collect.ImmutableList
import com.google.common.collect.ImmutableMap

internal data class Headers(
    val compression: Compression,
    val cipher: Cipher,
    val masterSeed: ByteString,
    val encryptionIv: ByteString,
    val kdf: Kdf,
    val publicCustomData: ImmutableMap<String, Any>
)

internal data class InnerHeaders(
    val innerRandomStreamKey: ByteString,
    val binaries: ImmutableList<Binary>
)
