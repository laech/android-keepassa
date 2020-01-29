package l.keepassa.kdbx

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal fun sha256(vararg inputs: ByteArray): ByteArray =
    hash("SHA-256", *inputs)

internal fun sha512(vararg inputs: ByteArray): ByteArray =
    hash("SHA-512", *inputs)

private fun hash(algorithm: String, vararg inputs: ByteArray): ByteArray {
    val hasher = MessageDigest.getInstance(algorithm)
    inputs.forEach(hasher::update)
    return hasher.digest()
}

internal fun hmacSha256(key: ByteArray): Mac {
    val algorithm = "HmacSHA256"
    val hasher = Mac.getInstance(algorithm)
    hasher.init(SecretKeySpec(key, algorithm))
    return hasher
}

internal fun hmacSha256(key: ByteArray, vararg inputs: ByteArray): ByteArray {
    val algorithm = "HmacSHA256"
    val hasher = Mac.getInstance(algorithm)
    hasher.init(SecretKeySpec(key, algorithm))
    inputs.forEach(hasher::update)
    return hasher.doFinal()
}
