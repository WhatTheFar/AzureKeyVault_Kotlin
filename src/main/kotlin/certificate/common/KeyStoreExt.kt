package certificate.common

import java.security.KeyStore

fun KeyStore.getFirstAlias(): String? {
    return aliases().takeIf { it.hasMoreElements() }?.nextElement()
}

fun KeyStore.getAliasWithPrivateKey(): String? {
    val aliases = aliases()
    var alias: String? = null
    while (aliases.hasMoreElements()) {
        alias = aliases.nextElement().takeIf { isKeyEntry(it) }
    }

    return alias
}