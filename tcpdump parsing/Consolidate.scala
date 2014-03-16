import java.io.{FileWriter, FileInputStream, File}
import scala.collection.immutable.StringOps
import scala.collection.mutable
import scala.io.Source

/**
 * This scala object is used to merge all data from CSV file produce by Parse scala object
 * into one CSV file.
 */
object Consolidate {

  var clientStats : mutable.Map[String, mutable.Map[String, Int]] = mutable.ListMap()
  var webServices : mutable.Map[String, Int] = mutable.ListMap()
  var clients : mutable.Map[String, Int] = mutable.ListMap()
  var filesProcessed = mutable.MutableList[String]()

  def main(args: Array[String]) {

    val DIR = new File("D:/tmp/dump/Fevrier_2014.csv/")
    val resultFile = "D:/tmp/dump/"+DIR.getName+"_consolidate.csv"
    val files: Array[File] = DIR.listFiles()

    files.foreach(file=>{
      filesProcessed+=file.getName
      val lines = Source.fromFile(file).getLines().toList
      val ops = lines.head.split(';').tail
      lines.tail.foreach(l => {
          val ls = l.split(';')
          val ip = ls.head
        (ls.tail, ops).zipped.foreach((value,op)=>incrementCount(ip, op, value.toInt))
      })
    })
    saveResultInFile(resultFile)
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
    out.append(";\n")
    out.append("Files processed:;\n")
    filesProcessed.foreach(f => out.append(f+";\n"))
    FileUtils.writeToFile(filename, out.toString())
    webServices.clear()
    clients.clear()
    clientStats.clear()
  }

  def incrementCount(client:String, operation:String, value:Int){
    webServices(operation) = webServices.getOrElse(operation, 0)+value
    clients(client) = clients.getOrElse(client, 0)+value
    val opCallPerClient = clientStats.getOrElseUpdate(client, mutable.ListMap())
    opCallPerClient(operation) = opCallPerClient.getOrElse(operation, 0)+value
  }
}
