package kdbx

import java.util.*
import kotlin.NoSuchElementException

internal sealed class Kdf {
    //AES_KDBX3("c9d9f39a-628a-4460-bf74-0d08c18a4fea"),

    companion object {
        private val uuidAes =
            UUID.fromString("7c02bb82-79a7-4ac0-927d-114a00648238")
        private val uuidArgon2 =
            UUID.fromString("ef636ddf-8c29-444b-91f7-a9a403e30a0c")

        fun from(params: Map<String, Any>): Kdf =
            when (readUuid(params.require("\$UUID"))) {
                uuidAes -> Aes.from(params)
                uuidArgon2 -> Argon2.from(params)
                else -> throw IllegalArgumentException(
                    UUID.fromString(params.require("\$UUID")).toString()
                )
            }

        private fun readUuid(bytes: ByteString) =
            bytes.toReadonlyByteBuffer().run { UUID(long, long) }
    }

    data class Aes(val seed: ByteString, val rounds: Int) : Kdf() {
        companion object {
            fun from(params: Map<String, Any>) = Aes(
                seed = params.require("S"),
                rounds = params.require("R")
            )
        }
    }

    data class Argon2(
        val version: Int,
        val salt: ByteString,
        val memory: Long,
        val iterations: Long,
        val parallelism: Int
    ) : Kdf() {
        companion object {
            fun from(params: Map<String, Any>) = Argon2(
                salt = params.require("S"),
                memory = params.require<String, Long>("M") / 1024.toLong(),
                version = params.require("V"),
                iterations = params.require("I"),
                parallelism = params.require("P")
            )
        }
    }
}

private inline fun <K, reified V> Map<K, Any?>.require(key: K): V {
    return get(key).let {
        if (it == null) {
            throw NoSuchElementException(key.toString())
        }
        if (it !is V) {
            throw ClassCastException("Cannot cast ${it::class.java} to ${V::class.java}")
        }
        it
    }
}
