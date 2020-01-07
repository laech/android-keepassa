package kdbx

import java.util.Collections.unmodifiableMap

internal class VariantMap private constructor(
    private val map: Map<Key<*>, Any>
) {
    interface Key<out T>

    @Suppress("UNCHECKED_CAST")
    operator fun <T> get(key: Key<T>): T? = map[key] as T?

    @Suppress("UNCHECKED_CAST")
    fun <T> require(key: Key<T>): T = get(key)
        ?: throw NoSuchElementException(key.toString())

    override fun toString(): String = map.toString()
    override fun hashCode() = map.hashCode()
    override fun equals(other: Any?) =
        other is VariantMap && map == other.map

    class Builder {
        private val map = HashMap<Key<*>, Any>()

        operator fun <T> set(key: Key<T>, value: T) {
            map[key] = value as Any
        }

        fun build() = VariantMap(unmodifiableMap(HashMap(map)))
    }
}
