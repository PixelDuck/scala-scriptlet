import java.io.{FileWriter, FileInputStream, File}
import scala.collection.immutable.StringOps
import scala.collection.mutable

/**
 * This class is able to parse a tcpdump file saved using pcap file format.
 * The goal is to identified all calls on LaraCIS web services done, and found which ip is the source of the call.
 * The web service is identified by the operation name.
 * The result is saved in a CSV file for each file processed. The scala object Condolidate
 * can be used to merge all CSV files into one file.
 *
 * PCAP format description is available on URL:
 * http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
 *
 * The analysis above is based on the first packet found from file Fevrier_2014/forte_mrs-as-00150_9292.tcpdump2
 *
 * ___HEADER___ 24 bytes                                                                        <============ to remove once
 * a1b2c3d4 : magic number (4 bytes)
 * 00020004 : version number (4 bytes)
 * 00000000: timezone (4 bytes)
 * 00000000: timezone precision (4 bytes)
 * 0000ffff: max length capture (4 bytes)
 * 00000001: link layer type (4 bytes)
 * ____PACKET HEADER____ 16 bytes
 * 52f8a449: epoch time (4 bytes)
 * 0008a7f5: microseconds capture (4 bytes)
 * 000005ea: size saved packet (4 bytes) 000005ea => 1514 bytes of data saved                  <============ 8 to 12 bytes from packet header
 * 000005ea: size captured packet (4 bytes) 000005ea => 1514 bytes of data captured
 * ____DATA____ 1514 bytes (size is retrieved from packet header
 * 00005e00001b : ethernet destination address (6 bytes)
 * 962df1dc7502 : ethernet source address (6 bytes)
 * 0800: Means IP (2 bytes)
 * 4500: something relative to IP header length (2 bytes)
 * 05dc: total length (2 bytes)
 * fce5: identification (2 bytes)
 * 4000: fragment offset (2 bytes)
 * 3c: time to live (1 byte)
 * 06: means TCP (1 byte)
 * ed41: header checksum (2 bytes)
 * 0a009013: ip source - means 10.0.144.19 (4 bytes)                                          <============ 26 to 30 bytes from data start
 * 0a00aae1: ip dest - means 10.0.170.225 (4 bytes)
 * 244c: source port (2 bytes)
 * f554: dest port (2 bytes)
 * eaf41e03: sequence number (4 bytes)
 * 47b6b6f5: acknowledgment number (4 bytes)
 * 5010: header length & flags (2 bytes)
 * ffff: windows size calculating factor (2 bytes)
 * 0000: checksum (2 bytes)
 * 0000: ??? (2 bytes)
 * Data until next packet                                                                     <============ 54 bytes
 */
object Parse {

  val BUFFER_SIZE = 1500

  val clientStats : mutable.Map[String, mutable.Map[String, Int]] = mutable.ListMap()
  val webServices : mutable.Map[String, Int] = mutable.ListMap()
  val clients : mutable.Map[String, Int] = mutable.ListMap()
  var fileBuffer = new mutable.StringBuilder()
  val bytesBuffer = new Array[Byte](BUFFER_SIZE)

  var fileBytesRead = 0L
  var count = 0
  var fileCount = 0
  var nbFiles = 0
  var fileLength = -1d
  var fileLengthAsLong = 0L
  var fileName = "unknown"
  var lastPercentageValueDisplayed = -1L

  def main(args: Array[String]) {
    val files: Array[File] = new File("D:/tmp/dump/Fevrier_2014/").listFiles()
    //val files: Array[File] = Array[File](new  File("D:/tmp/dump/Fevrier_2014/forte_mrs-as-00150_9292.tcpdump2"))
    //val files: Array[File] = Array[File](new  File("D:/tmp/dump/Fevrier_2014/forte_mrs-as-00012_9292.tcpdump"))

    nbFiles = files.length
    val start = System.currentTimeMillis()


    files.foreach(file=>{
      fileCount+=1
      val resultFileName = "D:/tmp/dump/Fevrier_2014.csv/"+file.getName+".csv"
      if(new File(resultFileName).exists()){
        printf(file.getName+" already processed. Skip It ["+fileCount+"/"+files.length+"]\n")
      } else {
        //open file
        val in = new FileInputStream(file)

        //init
        fileBytesRead = 0
        fileName = file.getName
        fileLength = Long.long2double(file.length)
        fileLengthAsLong = file.length
        lastPercentageValueDisplayed = -1
        count = 0

        //remove file header
        nextBytesAsString(in, 24*2)

        do{
          //read packet size
          val packetHeader = nextBytesAsString(in, 16*2)
          val packetLength = Hex.hex2int(packetHeader.substring(8*2, 12*2))

          //read packet
          val packetData = nextBytesAsString(in, packetLength*2)

          analyze(packetData)

          count += 1
        } while(in.available()>0 || fileBuffer.length>0 || count <10)


        in close()
        printf("\r"+file.getName+" size "+fileLength+" processed! ["+fileCount+"/"+files.length+"]\n")
        saveResultInFile(resultFileName)
      }
    })

    println("Time spent " + (System.currentTimeMillis()-start)+"ms")
  }


  def nextBytesAsString(in:FileInputStream, length: Int) : String = {
    try{
      while(fileBuffer.length<length && in.available()>0){
        val c = in.available()
        in.read(bytesBuffer)
        fileBuffer.append(Hex.valueOf(if(c<BUFFER_SIZE) bytesBuffer.slice(0, c) else bytesBuffer))
        fileBytesRead += Math.min(c, BUFFER_SIZE)
        val percentRead = (Long.long2double(fileBytesRead)/fileLength*100d).toInt
        if(percentRead!=lastPercentageValueDisplayed){
          printf("\rprocessing "+fileName+" size "+fileLengthAsLong+" ["+fileCount+"/"+nbFiles+"] "+percentRead+"%%")
          lastPercentageValueDisplayed = percentRead
        }
      }
      fileBuffer.take(length).toString()
    } finally {
      fileBuffer = fileBuffer.delete(0, length)
    }
  }

  def saveResultInFile(filename : String){
    val w = webServices.toSeq.sortBy(_._2).reverse.map(_._1)
    val out = new mutable.StringBuilder()
    out.append("ip;"+w.mkString(";")+"\n")
    val cl = clients.toSeq.sortBy(_._2).reverse
    cl.foreach(ip => {
      out.append(ip._1+";")
      val cs:mutable.Map[String,Int] = clientStats(ip._1)
      out.append(w.map(ws => cs.getOrElse(ws, 0)).mkString(";")+"\n")
    })

    FileUtils.writeToFile(filename, out.toString())
    webServices.clear()
    clients.clear()
    clientStats.clear()
  }

  def analyze(entry: String) {
    if(entry.length>30){
      var ipSource = convertToIp(entry.substring(26*2, 30*2))
      val soapContent = Hex.hexToString(entry.substring(54*2))
      val xffIndex = soapContent.indexOf("X-Forwarded-For: ")
      if(xffIndex > -1){
        val ipXffIndex = soapContent.indexOf("\r\n", xffIndex)
        ipSource = soapContent.substring(xffIndex+"X-Forwarded-For: ".length, ipXffIndex)
      }
      val envelopeIndex = soapContent.indexOf("Envelope")
      if(envelopeIndex > -1){
        if(soapContent.contains("Envelope")){
          val envelopeOpenBracket = soapContent.substring(0, envelopeIndex).lastIndexOf('<')
          if(envelopeOpenBracket > -1){
            if(soapContent.charAt(envelopeOpenBracket+1) != '/'){
              //find the open Envelope tag
              val envelope = soapContent.substring(envelopeOpenBracket, soapContent.length)
              val operation = extractOperation(envelope)
              if(!operation.endsWith("Response") && !operation.equals("unknown op")){
                incrementCount(ipSource, operation)
                count += 1
              }
            }
          }
        }
      }
    }
  }

  def incrementCount(client:String, operation:String){
    webServices(operation) = webServices.getOrElse(operation, 0)+1
    clients(client) = clients.getOrElse(client, 0)+1
    val opCallPerClient = clientStats.getOrElseUpdate(client, mutable.ListMap())
    opCallPerClient(operation) = opCallPerClient.getOrElse(operation, 0)+1
  }

  def extractOperation(envelope : String) : String ={
    val a = envelope.split('<')
    if(a.length>=4){
      val b = a(3).split('>')(0).split(' ')(0).split(':')
      return if(b.length>1) b(1) else b(0)
    }
    "unknown op"
  }

  def convertToIp(ipAsHex: String) : String = new StringOps(ipAsHex).sliding(2, 2).toList.map(Hex.hex2int).mkString(".")

}
