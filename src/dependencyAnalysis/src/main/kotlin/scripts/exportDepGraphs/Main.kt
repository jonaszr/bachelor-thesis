@file:Suppress("DuplicatedCode")

package scripts.exportDepGraphs

import common.createCondensedGraphFromMapping
import common.createMappingsFromCondensations
import common.getGraphSCCs
import common.group
import common.toJGraph
import common.DefaultGraph
import io.github.cdimascio.dotenv.Dotenv
import io.github.classgraph.ClassGraph
import io.github.classgraph.ClassInfoList
import io.github.classgraph.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import nonapi.io.github.classgraph.json.JSONDeserializer
import nonapi.io.github.classgraph.json.JSONSerializer
import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.bson.BsonDocument
import org.jgrapht.graph.DefaultEdge
import org.jgrapht.graph.builder.GraphTypeBuilder
import org.jgrapht.nio.dot.DOTImporter
import org.litote.kmongo.KMongo
import org.litote.kmongo.getCollection
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.net.URLClassLoader
import java.nio.file.Paths

class Main

private val dotenv = Dotenv.load()
private val dataDir = dotenv.get("DATA_DIR").let { Paths.get(it).toFile() }.also { it.mkdirs() }
private val jarsDir = dataDir.resolve("interim/jars").also { it.mkdirs() }
private val client = KMongo.createClient("mongodb://localhost:42692/")
private val db = client.getDatabase("s5_snyk_libio")
private val vulnCollection = db.getCollection<BsonDocument>("mergedVuln")

private val vulnGavToClasses = vulnCollection.find().useCursor { blk ->
    blk.map {
        val gav = it["vuln_gav"]!!.asString().value
        val vulnClasses = it["vuln_classes"]!!.asArray().map { it.asString().value }.toSet()

        if (vulnClasses.isEmpty()) throw Exception("no vuln class (record should have been omitted previously)")

        gav to vulnClasses
    }
}.groupBy { it.first }.map { g -> g.key to g.value.flatMap { it.second }.toSet() }.toMap()

private fun gavToJarUrl(packageGAV: String): String {
    val parts = packageGAV.split(":")
    return parts[0].replace('.', '/') + "/" + parts[1] + "/" + parts[2] + "/" + parts[1] + "-" + parts[2] + ".jar"
}

private val gavToJar = vulnGavToClasses.map {
    val jarPath = jarsDir.resolve(gavToJarUrl(it.key))
    if (!jarPath.isFile()) throw Exception(jarPath.name + " jar file not found")

    it.key to jarPath
}.toMap()

private fun loadJarIntoClassPath(jar: File): URLClassLoader =
    URLClassLoader(arrayOf(jar.toURI().toURL()))

private val dispatcher = Dispatchers.IO.limitedParallelism(8)

private fun saveCaches() =
    runBlocking {
        gavToJar.asSequence().windowed(1024, 1024, true).forEach { w ->
            System.gc()
            w.map {
                async(dispatcher) {
                    val gav = it.key
                    val jarFile = it.value

                    val (scanResultAsJson, jGraph, classes) = getDepGraphInfo(jarFile)

                    saveDepGraphInfo(classes, jGraph, gav, scanResultAsJson)
                    saveSCCs(jGraph, gav)

                    null
                }
            }.toList().awaitAll()
        }
    }

private fun getDepGraphInfo(jarFile: File) =
    loadJarIntoClassPath(jarFile).use { classLoader ->
        ClassGraph()
            .also { it.overrideClassLoaders(classLoader) }
            .enableInterClassDependencies()
            .enableAllInfo()
            .acceptJars(jarFile.name)
            .scan()
            .use { scanResult ->
                val analyzerPath = File(Main::class.java.protectionDomain.codeSource.location.toURI()).canonicalPath
                val classes = ClassInfoList(scanResult.allClasses.filterNot { it2 ->
                    it2.classpathElementFile.canonicalPath.contains(
                        analyzerPath
                    )
                }.filterNot { it2 -> it2.isExternalClass })

                val jGraph = classes.toJGraph(collapseInnerClasses = true)

                Triple(
                    JSONSerializer.serializeObject(classes, 2, false),
                    // scanResult.toJSON(2),
                    jGraph, classes
                )
            }
    }

private fun  saveDepGraphInfo(
    classes: ClassInfoList,
    jGraph: DefaultGraph,
    gav: String?,
    scanResultAsJson: String,
) {
    val allOuterClasses = classes.filter { jGraph.vertexSet().contains(it.name) }.toSet()

    if (allOuterClasses.map { it.name }.toSet().intersect(jGraph.vertexSet()).size != jGraph.vertexSet().size) {
        throw Exception("vertex set size mismatch $gav")
    }

    dataDir.resolve("interim/depGraphCache").also { it.mkdirs() }.resolve("$gav.vertices.tsv.zip").let { outFile ->
        allOuterClasses.joinToString("\n") { v ->
            "${v.name}\t${v.modifiers}"
        }.byteInputStream().use { inStream ->
            FileOutputStream(outFile).use { outFile ->
                CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, outFile)
                    .use { zipOut ->
                        inStream.copyTo(zipOut)
                    }
            }
        }
    }

    dataDir.resolve("interim/depGraphCache").also { it.mkdirs() }.resolve("$gav.edges.tsv.zip").let { outFile ->
        jGraph.edgeSet().joinToString("\n") { e ->
            "${jGraph.getEdgeSource(e)}\t${jGraph.getEdgeTarget(e)}"
        }.byteInputStream().use { inStream ->
            FileOutputStream(outFile).use { outFile ->
                CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, outFile)
                    .use { zipOut ->
                        inStream.copyTo(zipOut)
                    }
            }
        }
    }

    dataDir
        .resolve("interim/jarClassInfoCache")
        .also { it.mkdirs() }
        .resolve("$gav.classInfo.json.zip")
        .let { outFile ->
            scanResultAsJson.byteInputStream().use { inStream ->
                FileOutputStream(outFile).use { outFile ->
                    CompressorStreamFactory()
                        .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, outFile)
                        .use { zipOut ->
                            inStream.copyTo(zipOut)
                        }
                }
            }
        }
}

private fun saveSCCs(jGraph: DefaultGraph, gav: String?) {
    val depGraphSCCs = getGraphSCCs(jGraph)
    val (sccRootToVertexSet, vertexToSccRoot) = createMappingsFromCondensations(depGraphSCCs)
    val sccGraph = createCondensedGraphFromMapping(jGraph, vertexToSccRoot)

    val sccRootToId = sccGraph.vertexSet().sorted().mapIndexed { index, s -> s to index }.toMap()

    dataDir.resolve("interim/depGraphCache.scc").also { it.mkdirs() }.let { sccDir ->
        sccDir.resolve("$gav.dot").let { outFile ->
            val txt = StringBuilder()
            txt.append("strict digraph G {\n")

            sccRootToId.values.sorted().forEach { v ->
                txt.append("  $v;\n")
            }

            sccGraph.edgeSet().forEach { e ->
                txt.append(
                    "  ${sccRootToId[sccGraph.getEdgeSource(e)]!!} -> ${
                        sccRootToId[sccGraph.getEdgeTarget(e)]
                    };\n"
                )
            }

            txt.append("}\n")
            outFile.writeText(txt.toString())
            // DOTExporter<String, DefaultEdge>().also {
            //     it.setVertexIdProvider { v ->
            //         sccRootToId[v]!!.toString()
            //     }
            // }.also { it.exportGraph(sccGraph, outFile) }
        }

        sccDir.resolve("$gav.v2id.tsv").let { outFile ->
            outFile.writeText(sccRootToId.entries.joinToString("\n") {
                it.key + "\t" + it.value
            })
        }

        sccDir.resolve("$gav.v2r.tsv").let { outFile ->
            outFile.writeText(vertexToSccRoot.entries.joinToString("\n") {
                it.key + "\t" + it.value
            })
        }
    }
}

fun loadScanResultFromCache(gav: String): ScanResult {
    val outputJson = dataDir.resolve("interim/jarClassInfoCache/$gav.scanResult.json.zip")
    if (!outputJson.isFile) throw FileNotFoundException("cache file not found ${outputJson.absolutePath}")

    val jsonData = outputJson.inputStream().use { inputStream ->
        CompressorStreamFactory()
            .createCompressorInputStream(CompressorStreamFactory.DEFLATE, inputStream)
            .use { cInput ->
                cInput.readAllBytes()
            }
    }.toString(Charsets.UTF_8)

    return ScanResult.fromJSON(jsonData)
}

fun loadClassInfoListFromCache(gav: String): ClassInfoList {
    val outputJson = dataDir.resolve("interim/jarClassInfoCache/$gav.classInfo.json.zip")
    if (!outputJson.isFile) throw FileNotFoundException("cache file not found ${outputJson.absolutePath}")

    val jsonData = outputJson.inputStream().use { inputStream ->
        CompressorStreamFactory()
            .createCompressorInputStream(CompressorStreamFactory.DEFLATE, inputStream)
            .use { cInput ->
                cInput.readAllBytes()
            }
    }.toString(Charsets.UTF_8)

    return JSONDeserializer.deserializeObject(ClassInfoList::class.java, jsonData)
}

fun loadDepGraphFromCache(gav: String) =
    dataDir.resolve("interim/depGraphCache/$gav.vertices.tsv.zip").let { vCache ->
        if (!vCache.isFile) throw FileNotFoundException("cache file not found ${vCache.absolutePath}")

        val eCache = dataDir.resolve("interim/depGraphCache/$gav.edges.tsv.zip")
        if (!eCache.isFile) throw FileNotFoundException("cache file not found ${eCache.absolutePath}")

        val g =
            GraphTypeBuilder
                .directed<String, DefaultEdge>()
                .allowingMultipleEdges(false)
                .allowingSelfLoops(false)
                .edgeClass(DefaultEdge::class.java)
                .weighted(false)
                .buildGraph()

        vCache.inputStream().use { inputStream ->
            CompressorStreamFactory()
                .createCompressorInputStream(CompressorStreamFactory.DEFLATE, inputStream)
                .use { cInput ->
                    cInput.readAllBytes()
                }
        }.toString(Charsets.UTF_8).lines().filterNot { it.isBlank() }.forEach { l ->
            val parts = l.trim().split('\t')
            g.addVertex(parts[0].trim())
        }

        eCache.inputStream().use { inputStream ->
            CompressorStreamFactory()
                .createCompressorInputStream(CompressorStreamFactory.DEFLATE, inputStream)
                .use { cInput ->
                    cInput.readAllBytes()
                }
        }.toString(Charsets.UTF_8).lines().filterNot { it.isBlank() }.forEach { l ->
            val e = l.split('\t')
            g.addEdge(e[0].trim(), e[1].trim())
        }

        g
    }

/**
 * Returns map of vertex label to ClassGraph's modifier integer.
 * To check if a vertex (class) is public you should call Modifier.isPublic(modifiers)
 */
fun loadVertexInfo(gav: String) =
    dataDir.resolve("interim/depGraphCache/$gav.vertices.tsv.zip").let { vCache ->
        if (!vCache.isFile) throw FileNotFoundException("cache file not found ${vCache.absolutePath}")

        val eCache = dataDir.resolve("interim/depGraphCache/$gav.edges.tsv.zip")
        if (!eCache.isFile) throw FileNotFoundException("cache file not found ${eCache.absolutePath}")

        vCache.inputStream().use { inputStream ->
            CompressorStreamFactory()
                .createCompressorInputStream(CompressorStreamFactory.DEFLATE, inputStream)
                .use { cInput ->
                    cInput.readAllBytes()
                }
        }.toString(Charsets.UTF_8).lines().filterNot { it.isBlank() }.associate { l ->
            val parts = l.trim().split('\t')
            parts[0].trim() to parts[1].trim().toInt()
        }
    }

fun loadDepGraphFromDotFile(gav: String) =
    dataDir.resolve("interim/depGraphCache.scc/$gav.dot").let { dotFile ->
        if (!dotFile.isFile) throw FileNotFoundException("dot file not found ${dotFile.absolutePath}")

        val graph =
            GraphTypeBuilder
                .directed<String, DefaultEdge>()
                .allowingMultipleEdges(false)
                .allowingSelfLoops(false)
                .edgeClass(DefaultEdge::class.java)
                .weighted(false)
                .buildGraph()

        val sccRootToId = dataDir.resolve("interim/depGraphCache.scc/$gav.v2id.tsv").let { f ->
            if (!f.isFile) throw FileNotFoundException("v2id file not found ${f.canonicalPath}")
            val sccRootToId = f.readLines().map { it.split("\t") }.associate { it[0] to it[1] }
            if (sccRootToId.isEmpty()) error("v2id is empty ${f.canonicalPath}")
            sccRootToId
        }

        val sccIdToLabel = sccRootToId.entries.associate { it.value to it.key }

        val importer = DOTImporter<String, DefaultEdge>().also {
            it.setVertexFactory { v ->
                sccIdToLabel[v]!!
            }
        }
        importer.importGraph(graph, dotFile)
        null
    }

fun loadSccMappingInfo(gav: String) {
    dataDir.resolve("interim/depGraphCache.scc/$gav.v2r.tsv").let { f ->
        if (!f.isFile) throw FileNotFoundException("v2r file not found ${f.canonicalPath}")
        val vertexToSccRoot = f.readLines().map { it.split("\t") }.associate { it[0] to it[1] }
        if (vertexToSccRoot.isEmpty()) error("v2r is empty ${f.canonicalPath}")
        vertexToSccRoot.group().let { }
    }
}

private fun checkCaches() {
    val dispatcher = Dispatchers.IO.limitedParallelism(256)

    gavToJar.asSequence().windowed(1024, 1024, true).forEach { w ->
        System.gc()
        runBlocking {
            w.map {
                async(dispatcher) {
                    try {
                        // loadClassInfoListFromCache(it.key).let { }
                        // loadScanResultFromCache(it.key).let { }
                        // loadDepGraphFromCache(it.key).let { }
                        // loadVertexInfo(it.key).let { }
                        loadDepGraphFromDotFile(it.key).let { }
                        loadSccMappingInfo(it.key).let { }
                        null
                    } catch (e: FileNotFoundException) {
                        println("file not found ${it.key} ${e.message}")
                    } catch (e: Exception) {
                        println("error ${it.key} ${e.message} ${e.stackTraceToString()}")
                    }
                }
            }.toList().awaitAll().toList()
        }
    }
}

private fun main() {
    println(gavToJar.size)
    saveCaches()
    checkCaches()
}