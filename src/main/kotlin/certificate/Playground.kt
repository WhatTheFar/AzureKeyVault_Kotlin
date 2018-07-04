package certificate

fun main(args: Array<String>) {
    val i = -34
    val b = i.toByte()
    val s = b.toPositiveInt() shl 4

    println(Integer.toBinaryString(i))
    println("i $i")
    println("b $b")
    println("b.toPositiveInt ${b.toPositiveInt()}")
    println("b.toPositiveInt ${b.toPositiveInt().toBinaryString()}")
    println(Integer.toBinaryString(s.toByte().toPositiveInt()))
}

fun Byte.toPositiveInt() = toInt() and 0xFF

fun Int.toBinaryString() = Integer.toBinaryString(this)