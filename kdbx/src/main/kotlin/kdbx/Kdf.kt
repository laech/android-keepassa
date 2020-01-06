package kdbx

import java.util.*
import kotlin.NoSuchElementException

internal sealed class Kdf {

    companion object {
        fun from(params: Map<String, Any>): Kdf =
            when (val uuid = readUuid(params.require("\$UUID"))) {
                Aes.uuid -> Aes.from(params)
                Argon2.uuid -> Argon2.from(params)
                else -> throw IllegalArgumentException("Unknown KDF: $uuid")
            }

        private fun readUuid(bytes: ByteString) =
            bytes.toReadonlyByteBuffer().run { UUID(long, long) }
    }

    // https://github.com/keepassxreboot/keepassxc/blob/2.5.1/src/crypto/kdf/AesKdf.cpp
    data class Aes(val seed: ByteString, val rounds: Int) : Kdf() {

        init {
            validateSeed()
            validateRounds()
        }

        private fun validateSeed() {
            if (seed.size !in 8..32) {
                throw IllegalArgumentException("seed.size=${seed.size}")
            }
        }

        private fun validateRounds() {
            if (rounds !in 1 until Int.MAX_VALUE) {
                throw IllegalArgumentException("rounds=$rounds")
            }
        }

        companion object {
            internal val uuid = UUID.fromString(
                "7c02bb82-79a7-4ac0-927d-114a00648238"
            )

            fun from(params: Map<String, Any>) = Aes(
                seed = params.require("S"),
                rounds = params.require("R")
            )
        }
    }

    // https://github.com/keepassxreboot/keepassxc/blob/2.5.1/src/crypto/kdf/Argon2Kdf.cpp
    data class Argon2(
        val version: Int,
        val salt: ByteString,
        val memoryKb: Long,
        val iterations: Long,
        val parallelism: Int
    ) : Kdf() {

        init {
            validateSalt()
            validateVersion()
            validateMemory()
            validateParallelism()
            validateIterations()
        }

        private fun validateSalt() {
            if (salt.size !in 8..32) {
                throw IllegalArgumentException("salt.size=${salt.size}")
            }
        }

        private fun validateIterations() {
            if (iterations !in 1 until Int.MAX_VALUE) {
                throw IllegalArgumentException("iterations=$iterations")
            }
        }

        private fun validateParallelism() {
            if (parallelism !in 1..(1 shl 24)) {
                throw IllegalArgumentException("parallelism=$parallelism")
            }
        }

        private fun validateMemory() {
            if (memoryKb !in 8 until (1L shl 32)) {
                throw IllegalArgumentException("memoryKb=$memoryKb")
            }
        }

        private fun validateVersion() {
            if (version !in 0x10..0x13) {
                throw IllegalArgumentException("version=$version")
            }
        }

        companion object {
            internal val uuid = UUID.fromString(
                "ef636ddf-8c29-444b-91f7-a9a403e30a0c"
            )

            fun from(params: Map<String, Any>) = Argon2(
                salt = params.require("S"),
                memoryKb = params.require<String, Long>("M") / 1024.toLong(),
                version = params.require("V"),
                iterations = params.require("I"),
                parallelism = params.require("P")
            )
        }
    }
}

private inline fun <K, reified V> Map<K, Any?>.require(key: K): V =
    get(key).let {
        if (it == null) {
            throw NoSuchElementException("key=$key")
        }
        if (it !is V) {
            throw ClassCastException("Cannot cast ${it::class.java} to ${V::class.java}")
        }
        it
    }
