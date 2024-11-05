package scripts.partitionDepGraph.dagP

import io.github.cdimascio.dotenv.Dotenv
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.bson.BsonDocument
import org.jgrapht.graph.DefaultEdge
import org.jgrapht.graph.builder.GraphTypeBuilder
import org.jgrapht.nio.dot.DOTImporter
import org.litote.kmongo.KMongo
import org.litote.kmongo.getCollection
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.file.Paths
import java.util.concurrent.TimeUnit
import kotlin.time.measureTime

class Main

val dotenv = Dotenv.load()
val dataDir = dotenv.get("DATA_DIR").let { Paths.get(it).toFile() }.also { it.mkdirs() }

val client = KMongo.createClient("mongodb://localhost:42692/")
val db = client.getDatabase("s5_snyk_libio")
val vulnCollection = db.getCollection<BsonDocument>("mergedVuln")

val vulnGavs = vulnCollection.find().useCursor { blk ->
    blk.map {
        it["vuln_gav"]!!.asString().value
    }
}.toSet()

val gavToSccFile = vulnGavs.associateWith {
    val sccFile = dataDir.resolve("interim/depGraphCache.scc").resolve("${it}.dot")
    if (!sccFile.isFile()) throw Exception("dot file not found")
    sccFile
}

val dispatcher = Dispatchers.IO.limitedParallelism(8)

fun runDagpOnDepGraph(gav: String) {
    val dagpExe = dotenv.get("DAGP_EXE").let { Paths.get(it).toFile() }
    val rmlgpExec = dagpExe.resolve("rMLGP").canonicalPath
    
    val dotFile = dataDir.resolve("interim/depGraphCache.scc/$gav.dot")
    
    val graph = GraphTypeBuilder
        .directed<String, DefaultEdge>()
        .allowingMultipleEdges(false)
        .allowingSelfLoops(false)
        .edgeClass(DefaultEdge::class.java)
        .weighted(false)
        .buildGraph()
    
    val sccIdToLabel = dataDir.resolve("interim/depGraphCache.scc/$gav.v2id.tsv").let { f ->
        f.readLines().map { it.split("\t") }.associate { it[1] to it[0] }
    }
    
    DOTImporter<String, DefaultEdge>().also {
        it.setVertexFactory { v ->
            sccIdToLabel[v]!!
        }
    }.also { it.importGraph(graph, dotFile) }
    
    val partitionCount = when (graph.vertexSet().size) {
        in 1 .. 16 -> 1
        in 17 .. 64 -> 2
        in 65 .. 256 -> 4
        in 257 .. 1024 -> 8
        in 1025 .. 4096 -> 16
        in 4097 .. 8192 -> 32
        else -> 64
    }
    
    val seed = 42
    val runs = 100
    
    dataDir.resolve("interim/depGraphCache.scc/$gav.outDetails.tsv").writeText(
        "partsFile\t$gav.dot.partsfile.part_$partitionCount.seed_$seed.txt\npartitionCount\t$partitionCount\nruns\t$runs"
    )
    
    val args = "--write_parts 1 --runs $runs --seed $seed"
    val cmd = "$rmlgpExec ${dotFile.canonicalPath} $partitionCount $args"
    val p = Runtime.getRuntime().exec(cmd)
    println("waiting for ${dotFile.canonicalPath}")
    BufferedReader(InputStreamReader(p.inputStream)).use { b ->
        while (b.readLine() != null) { // noop
        }
    }
    if (!p.waitFor(120, TimeUnit.SECONDS)) {
        p.destroy()
        println("error ${dotFile.canonicalPath}")
    }
    println("done ${dotFile.canonicalPath}")
}

fun runDagpOnDepGraphs() {
    runBlocking {
        vulnGavs.asSequence().shuffled().windowed(256, 256, true).forEach { w ->
            System.gc()
            w.map {
                async(dispatcher) {
                    runDagpOnDepGraph(it)
                }
            }.toList().awaitAll()
        }
    }
}

data class DagpPartInfo(
    val gav: String,
    val partitionCount: Int,
    val vertexToPart: Map<String, Int>,
    val partToVertices: Map<Int, Set<String>>,
)

fun loadDagpPartitionInfo(gav: String): DagpPartInfo {
    val details = dataDir.resolve("interim/depGraphCache.scc/$gav.outDetails.tsv").readLines().map {
        it.split("\t")
    }.associate {
        it[0] to it[1]
    }
    
    val sccRoots = dataDir.resolve("interim/depGraphCache.scc").resolve("$gav.v2id.tsv").readLines().map { it.split("\t")[0] }
    
    val partsList = if (sccRoots.size == 1) listOf(0)
    else dataDir.resolve("interim/depGraphCache.scc").resolve(details["partsFile"]!!).readLines().map {
        it.toInt()
    }
    
    if (partsList.size != sccRoots.size) {
        error("size mismatch between partsfile and v2id")
    }
    
    val sccRootToPartId = sccRoots.zip(partsList).associate { it.first to it.second }
    
    if (sccRootToPartId.size != sccRoots.size) {
        error("duplicate vertex label")
    }
    
    val vertexToSccRoot =
        dataDir.resolve("interim/depGraphCache.scc").resolve("$gav.v2r.tsv").readLines().map { it.split("\t") }.associate { it[0] to
                it[1] }
    
    val vertexToPartId = vertexToSccRoot.map { v2r ->
        v2r.key to sccRootToPartId[v2r.value]!!
    }.toMap()
    
    return DagpPartInfo(gav = gav,
                        partitionCount = details["partitionCount"]!!.toInt(),
                        vertexToPart = vertexToPartId,
                        partToVertices = vertexToPartId.asSequence().groupBy { it.value }.map {
                            it.key to it.value.map { it2 -> it2.key }.toSet()
                        }.toMap()
    )
}

private fun loadAllDagpPartitionInfo() {
    runBlocking {
        vulnGavs.asSequence().shuffled().windowed(256, 256, true).forEach { w ->
            System.gc()
            w.map {
                async(dispatcher) {
                    loadDagpPartitionInfo(it).let { }
                }
            }.toList().awaitAll()
        }
    }
}

fun main() {
    val t = measureTime {
        runDagpOnDepGraphs()
    }
    
    println("it took ${t.inWholeMilliseconds} ms")
    
    // println(vulnGavs.size)
    // println(gavToSccFile.size)
    
    // loadAllDagpPartitionInfo()
}