@file:OptIn(ExperimentalCoroutinesApi::class)
@file:Suppress("DuplicatedCode", "PropertyName", "LocalVariableName", "UnusedImport")

package scripts.modularityAlignment

import common.format
import common.gsonSerializer
import io.github.cdimascio.dotenv.Dotenv
import java.nio.file.Paths
import kotlin.reflect.full.memberProperties
import kotlin.reflect.full.primaryConstructor
import kotlin.reflect.jvm.isAccessible
import kotlin.reflect.typeOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.bson.BsonDocument
import org.jetbrains.letsPlot.*
import org.jetbrains.letsPlot.coord.coordFlip
import org.jetbrains.letsPlot.export.*
import org.jetbrains.letsPlot.geom.*
import org.jetbrains.letsPlot.label.*
import org.jetbrains.letsPlot.letsPlot
import org.jetbrains.letsPlot.scale.*
import org.jetbrains.letsPlot.themes.*
import org.litote.kmongo.KMongo
import org.litote.kmongo.getCollection
import org.nield.kotlinstatistics.median
import org.nield.kotlinstatistics.standardDeviation
import scripts.partitionDepGraph.dagP.loadDagpPartitionInfo

private val dotenv = Dotenv.load()
private val dataDir = dotenv.get("DATA_DIR").let { Paths.get(it).toFile() }.also { it.mkdirs() }

private val cacheDir =
    dataDir.resolve("interim/modularityAlignment").also { it.mkdirs() }
private val cacheFile = cacheDir.resolve("alignment.tsv")

private val experimentOutputDir =
    dataDir.resolve("proc/modularityAlignment").also { it.mkdirs() }

private fun Any.toTsvString(
    listDelim: String = ";",
    mapDelim: String = ":",
): String {
    return when (this) {
        is List<*>   -> this.joinToString(listDelim) { it!!.toTsvString() }
        is Map<*, *> ->
            this.asSequence().joinToString(listDelim) {
                it.key!!.toTsvString() + mapDelim + it.value!!.toTsvString()
            }
        
        else         -> this.toString()
    }
}

private fun List<AnalysisResult>.toTsv(): String {
    AnalysisResult::class.members.forEach { it.isAccessible = true }
    val ctor = AnalysisResult::class.primaryConstructor!!
    ctor.isAccessible = true
    val properties = AnalysisResult::class.memberProperties.sortedBy { it.name }
    val header = properties.joinToString("\t") { it.name }
    val lines =
        this.joinToString("\n") { v -> properties.joinToString("\t") { it.get(v)!!.toTsvString() } }
    return "$header\n$lines"
}

private fun loadAnalysisResultFromCache(
    listDelim: Char = ';',
    mapDelim: Char = ':',
): List<AnalysisResult> {
    val lines = cacheFile.readLines()
    val header = lines[0].split("\t").mapIndexed { i, s -> s to i }.toMap()
    return lines.drop(1).map { l ->
        val parts = l.split('\t')
        val ctor = AnalysisResult::class.primaryConstructor!!
        val args =
            ctor.parameters
                .map { param ->
                    val x = parts[header[param.name]!!]
                    when (param.type) {
                        typeOf<Double>()        -> x.toDouble()
                        typeOf<Int>()           -> x.toInt()
                        typeOf<String>()        -> x
                        typeOf<List<Double>>()  -> x.split(listDelim).map { it.toDouble() }
                        typeOf<List<Int>>()     -> x.split(listDelim).map { it.toInt() }
                        typeOf<Map<Int, Int>>() ->
                            x.split(listDelim).associate {
                                val kv = it.split(mapDelim)
                                kv[0].toInt() to kv[1].toInt()
                            }
                        
                        else                    -> throw Error("invalid type")
                    }
                }
                .toTypedArray()
        AnalysisResult::class.members.forEach { it.isAccessible = true }
        ctor.isAccessible = true
        ctor.call(*args)
    }
}

private data class AnalysisResult(
    val depGav: String,
    val classCount: Int,
    val moduleCount: Int,
    val packageCount: Int,
    val numberOfPackagesInSingleModule: Int,
    val moduleSizeMean: Double,
    val moduleSizeMedian: Double,
    val numberOfPackagesInNModules: Map<Int, Int>,
    val packageToPartitionRatio: List<Double>,
    val packageToPartitionCount: List<Int>,
)

private class Analysis(loadFromCache: Boolean = true) {
    
    private val analysisOutputFile = experimentOutputDir.resolve("output.txt")
    private val analysisOutputSb = StringBuilder()
    
    private val mongoClient by lazy { KMongo.createClient("mongodb://localhost:42692/") }
    private val snykLibioDb by lazy { mongoClient.getDatabase("s5_snyk_libio") }
    private val vulnCollection by lazy {
        snykLibioDb.getCollection<BsonDocument>("mergedVuln")
    }
    
    // private val vulnClientCollection by lazy {
    // snykLibioDb.getCollection<BsonDocument>("mergedVulnClients") }
    
    private val vulnGavs by lazy {
        vulnCollection
            .find()
            .useCursor { blk -> blk.map { it["vuln_gav"]!!.asString().value } }
            .sorted()
            .groupBy { it.split(':').take(2).joinToString(":") }
            .map { it.value.first() }
            .also { analysisOutputSb.appendLine("vulnGavs.count(): ${it.count()}") }
    }
    
    private val partitionInfo by lazy {
        vulnGavs.associateWith { loadDagpPartitionInfo(it) }.also {
            analysisOutputSb.appendLine("partitionInfo.count(): ${it.count()}")
        }
    }
    
    private fun runAnalysis() =
        Dispatchers.IO.limitedParallelism(32).let { dispatcher ->
            vulnGavs
                .asSequence()
                .windowed(512, 512, true)
                .flatMapIndexed { batch, w ->
                    runBlocking {
                        System.gc()
                        println("processing batch $batch")
                        w
                            .map {
                                async(dispatcher) {
                                    val depGav = it
                                    val partitionInfo = partitionInfo[depGav]!!
                                    
                                    val packageToPartition =
                                        partitionInfo
                                            .vertexToPart
                                            .asSequence()
                                            .groupBy { (v, _) ->
                                                v.split('.').dropLast(1).joinToString(separator = ".")
                                            }
                                            .map { g -> g.key to g.value.map { p -> p.value }.toSet() }
                                            .toMap()
                                    
                                    val packageToPartitionCount =
                                        packageToPartition.asSequence().associate { (k, v) -> k to v.size }
                                    
                                    val packageToPartitionCountRatio =
                                        packageToPartitionCount.asSequence().associate { (k, v) ->
                                            k to v / partitionInfo.partitionCount.toDouble()
                                        }
                                    
                                    val res =
                                        AnalysisResult(
                                            depGav = it,
                                            classCount = partitionInfo.vertexToPart.keys.size,
                                            packageCount = packageToPartitionCount.keys.size,
                                            moduleCount = partitionInfo.partitionCount,
                                            moduleSizeMean =
                                            partitionInfo
                                                .partToVertices
                                                .map { it.value.size.toDouble() }
                                                .average(),
                                            moduleSizeMedian =
                                            partitionInfo
                                                .partToVertices
                                                .map { it.value.size.toDouble() }
                                                .median(),
                                            numberOfPackagesInSingleModule =
                                            packageToPartitionCount.count { it.value == 1 },
                                            packageToPartitionCount =
                                            packageToPartitionCount.values.toList(),
                                            packageToPartitionRatio =
                                            packageToPartitionCountRatio.values.toList(),
                                            numberOfPackagesInNModules =
                                            packageToPartitionCount
                                                .asSequence()
                                                .groupBy { it.value }
                                                .map { it.key to it.value.size }
                                                .toMap()
                                        )
                                    
                                    return@async Result.success(res)
                                }
                            }
                            .toList()
                            .awaitAll()
                            .toList()
                    }
                        .toList()
                        .filter { it.isSuccess }
                        .map { it.getOrNull()!! }
                        .toList()
                }
                .toList()
        }
    
    val analysisResult =
        if (loadFromCache) {
            loadAnalysisResultFromCache()
        } else {
            val vulnInfo = runAnalysis()
            cacheFile.writeText(vulnInfo.toTsv())
            vulnInfo
        }
            .also { analysisOutputSb.appendLine("analysis result count: ${it.size}") }
    
    init {
        analysisOutputFile.writeText(analysisOutputSb.toString())
    }
}

private class PostAnalysis(analysis: Analysis) {
    
    private val _aRes = analysis.analysisResult
    
    private val plots =
        mapOf(
            Pair(
                "ModuleCountHistogram",
                letsPlot(mapOf(Pair("number of modules", _aRes.map { it.moduleCount }))) {
                    x = "number of modules"
                } +
                  ggsize(800, 600) +
                  geomHistogram(alpha = .3, binWidth = 1, center = .5) +
                  xlim(limits = Pair(0, 40))
            ),
            Pair(
                "ModuleSizeHistogram_Mean",
                letsPlot(
                    mapOf(
                        Pair(
                            "mean(#classes per module  / #classes per library)",
                            _aRes.map { it.moduleSizeMean }
                        )
                    )
                ) { x = "mean(#classes per module  / #classes per library)" } +
                  ggsize(800, 500) +
                  geomHistogram(alpha = .3, binWidth = 1, center = .5) +
                  geomDensity { y = "..count.." } +
                  xlim(limits = Pair(0, 100)) +
                  themeBW() +
                  theme(
                      text = elementText(family = "Times New Roman", size = 26),
                      axisTitle = elementText(family = "Times New Roman", size = 28),
                  ),
            )
        ) +
          (1 .. 10).associate { n ->
              "${n}_ModulesPackageRatioHistogram" to
                letsPlot(
                    mapOf(
                        "ratio of ${n}-module packages" to
                          _aRes.map {
                              (it.numberOfPackagesInNModules[n]
                                  ?: 0) / it.packageCount.toDouble() * 100
                          }
                    )
                ) { x = "ratio of ${n}-module packages" } +
                ggsize(1200, 600) +
                geomHistogram(alpha = .3, binWidth = 10, center = .5) {
                    // y = "..density.."
                } +
                xlim(limits = Pair(0, 100))
          } +
          (1 .. 10).associate { n ->
              "X_PercentOfPkgsAreInAtMost_${n}_Modules" to
                letsPlot(
                    mapOf(
                        "ratio of packages" to
                          _aRes.map {
                              it.packageToPartitionCount.count { c -> c <= n } / it.packageCount.toDouble() * 100
                          }
                    )
                ) { x = "ratio of packages" } +
                ggsize(800, 600) +
                geomHistogram(alpha = .3, binWidth = 1, center = .5) +
                xlim(limits = Pair(0, 100))
          } +
          mapOf(
              "X_PercentOfPkgsAreInAtMost_N_Modules_Median" to
                letsPlot(
                    mapOf(
                        "median ratio of #packages that are at most in N modules" to
                          (1 .. 10).map { n ->
                              _aRes
                                  .map {
                                      it.packageToPartitionCount.count { c -> c <= n } / it.packageCount.toDouble() * 100
                                  }
                                  .median()
                          }
                    )
                ) {
                    y = "median ratio of #packages that are at most in N modules"
                    x = (1 .. 10)
                } +
                ggsize(800, 600) +
                geomPoint(alpha = 1, size = 5) +
                geomLine(alpha = 0.6) +
                xlim(limits = Pair(0, 10)) +
                themeGrey() +
                xlab("N"),
              "X_PercentOfPkgsAreInAtMost_N_Modules_Median_Box" to
                letsPlot(
                    mapOf(
                        "y" to
                          (1 .. 10).flatMap { n ->
                              _aRes.map { it.packageToPartitionCount.count { c -> c <= n } / it.packageCount.toDouble() * 100 }
                          },
                        "x" to
                          (1 .. 10).flatMap { n ->
                              _aRes.map { n }
                          },
                    )
                ) {
                    y = "y"
                    x = "x"
                } +
                ggsize(800, 500) +
                geomBoxplot() +
                xlab("N") +
                ylab("ratio of #packages in at most N modules per library") +
                coordFlip() +
                // themeGrey() +
                themeBW() +
                theme(
                    text = elementText(family = "Times New Roman", size = 26),
                    axisTitle = elementText(family = "Times New Roman", size = 28),
                ),
          )
    
    private val stats: Map<String, Any> =
        mapOf(
            "AnalysisResult" to
              AnalysisResult::class
                  .memberProperties
                  .mapNotNull { mp ->
                      when (mp.returnType) {
                          typeOf<Double>() ->
                              mp.name to
                                hashMapOf(
                                    "median" to
                                      _aRes
                                          .map { mp.get(it) as Double }
                                          .filterNot { it.isNaN() }
                                          .median()
                                          .format(2),
                                    "average" to
                                      _aRes
                                          .map { mp.get(it) as Double }
                                          .filterNot { it.isNaN() }
                                          .average()
                                          .format(2),
                                    "min" to
                                      _aRes
                                          .map { mp.get(it) as Double }
                                          .filterNot { it.isNaN() }
                                          .min()
                                          .format(2),
                                    "max" to
                                      _aRes
                                          .map { mp.get(it) as Double }
                                          .filterNot { it.isNaN() }
                                          .max()
                                          .format(2),
                                    "stddev" to
                                      _aRes
                                          .map { mp.get(it) as Double }
                                          .filterNot { it.isNaN() }
                                          .standardDeviation()
                                          .format(2),
                                )
                          
                          typeOf<Int>()    ->
                              mp.name to
                                hashMapOf(
                                    "median" to _aRes.map { mp.get(it) as Int }.median().format(2),
                                    "average" to _aRes.map { mp.get(it) as Int }.average().format(2),
                                    "min" to _aRes.minOfOrNull { mp.get(it) as Int },
                                    "max" to _aRes.maxOfOrNull { mp.get(it) as Int },
                                    "stddev" to
                                      _aRes.map { mp.get(it) as Int }.standardDeviation().format(2),
                                )
                          
                          else             -> null
                      }
                  }
                  .toMap(),
            "X_PercentOfPkgsAreInAtMost_N_Modules" to
              (1 .. 10).associate { n ->
                  "X_PercentOfPkgsAreInAtMost_${n}_Modules" to
                    _aRes
                        .map {
                            it.packageToPartitionCount.count { c -> c <= n } / it.packageCount.toDouble() * 100
                        }
                        .let {
                            mapOf(
                                "median" to it.median(),
                                "avg" to it.average(),
                                "min" to it.min(),
                                "max" to it.max(),
                                "stddev" to it.standardDeviation(),
                            )
                        }
              }
        )
    
    init {
        plots.forEach { (pName, p) ->
            ggsave(p, experimentOutputDir.resolve("${pName}.png").canonicalPath, dpi = 1200)
        }
        experimentOutputDir.resolve("postAnalysisStats.json").writeText(gsonSerializer.toJson(stats))
    }
}

private fun main() {
    val loadFromCache = true
    
    val analysis = Analysis(loadFromCache)
    val postAnalysis = PostAnalysis(analysis)
}
