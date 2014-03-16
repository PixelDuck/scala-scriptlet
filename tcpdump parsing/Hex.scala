
/**
 * Utilities on Hexadecimal
 */
object Hex {

    def valueOf(buf: Array[Byte]): String = buf.map("%02X" format _).mkString

   def hex2int (hex: String): Int = Integer.parseInt(hex, 16)

    def hex2byte(hex: String) : Byte = Integer.parseInt(hex, 16).toByte

   def hexToString(hex: String) : String = new String(hex.sliding(2, 2).toArray.map(Hex.hex2byte))
}
