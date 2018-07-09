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

    test()
}

fun Byte.toPositiveInt() = toInt() and 0xFF

fun Int.toBinaryString() = Integer.toBinaryString(this)

operator fun <T, R, V> ((T) -> R).rangeTo(other: (R) -> V): ((T) -> V) = { other(this(it)) }

fun same(v: Int) = v
fun twice(v: Int) = v * 2
fun trice(v: Int) = v * 3

fun test() {
    (::same..::twice..::trice..::println)(1)
    // 6
}