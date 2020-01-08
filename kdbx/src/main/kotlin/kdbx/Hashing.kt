package kdbx

import java.security.MessageDigest

internal fun sha256(vararg inputs: ByteArray): ByteArray {
    val hasher = MessageDigest.getInstance("SHA-256")
    inputs.forEach(hasher::update)
    return hasher.digest()
}
