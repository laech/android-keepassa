package kdbx

internal inline fun <K, reified V> Map<K, *>.getTyped(key: K): V? {
    val value = get(key)
    if (value != null && value !is V) {
        throw ClassCastException("Cannot cast ${value::class.java} to ${V::class.java}")
    }
    return value as V?
}

internal inline fun <K, reified V> Map<K, *>.getRequired(key: K): V =
    getTyped(key) ?: throw NoSuchElementException("$key")
