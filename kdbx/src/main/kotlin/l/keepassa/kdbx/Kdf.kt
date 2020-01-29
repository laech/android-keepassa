package l.keepassa.kdbx

import java.util.*
import org.signal.argon2.Argon2.Builder as Argon2Builder
import org.signal.argon2.Type as Argon2Type
import org.signal.argon2.Version as Argon2Version

internal sealed class Kdf {

    abstract fun transform(password: ByteArray): ByteArray

    companion object {
        fun from(params: Map<String, Any>): Kdf =
            when (val uuid = readUuid(params.getRequired("\$UUID"))) {
                Aes.uuid -> Aes.from(params)
                Argon2.uuid -> Argon2.from(params)
                else -> throw IllegalArgumentException("Unknown KDF: $uuid")
            }

        private fun readUuid(bytes: ByteString) =
            bytes.toReadonlyByteBuffer().run { UUID(long, long) }
    }

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

        override fun transform(password: ByteArray): ByteArray {
            TODO("not implemented")
        }

        companion object {
            internal val uuid =
                UUID.fromString("7c02bb82-79a7-4ac0-927d-114a00648238")

            fun from(params: Map<String, Any>) = Aes(
                seed = params.getRequired("S"),
                rounds = params.getRequired("R")
            )
        }
    }

    // https://github.com/keepassxreboot/keepassxc/blob/2.5.1/src/crypto/kdf/Argon2Kdf.cpp
    data class Argon2(
        val version: Argon2Version,
        val salt: ByteString,
        val memoryKb: Int,
        val iterations: Int,
        val parallelism: Int
    ) : Kdf() {

        init {
            validateSalt()
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

        override fun transform(password: ByteArray): ByteArray =
            Argon2Builder(version)
                .type(Argon2Type.Argon2d)
                .memoryCostKiB(memoryKb)
                .iterations(iterations)
                .parallelism(parallelism)
                .hashLength(32)
                .build()
                .hash(password, salt.toByteArray())
                .hash

        companion object {

            private val versions = mapOf(
                Pair(0x10, Argon2Version.V10),
                Pair(0x13, Argon2Version.V13)
            )

            internal val uuid =
                UUID.fromString("ef636ddf-8c29-444b-91f7-a9a403e30a0c")

            fun from(params: Map<String, Any>) = Argon2(
                salt = params.getRequired("S"),
                memoryKb = (params.getRequired<String, Long>("M") / 1024).toInt(),
                iterations = params.getRequired<String, Long>("I").toInt(),
                parallelism = params.getRequired("P"),
                version = params.getRequired<String, Int>("V").run {
                    versions[this]
                        ?: throw IllegalArgumentException("Unknown version $this")
                }
            )
        }
    }

}
