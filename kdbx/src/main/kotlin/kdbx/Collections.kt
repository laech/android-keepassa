package kdbx

import com.google.common.collect.ImmutableMap

internal fun <K, V> Sequence<Pair<K, V>>.toImmutableMap(): ImmutableMap<K, V> =
    fold(ImmutableMap.builder<K, V>(), { builder, (key, value) ->
        builder.put(key, value)
        builder
    }).build()
