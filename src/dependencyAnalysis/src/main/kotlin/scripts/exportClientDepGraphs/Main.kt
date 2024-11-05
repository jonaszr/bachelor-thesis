@file:Suppress("DuplicatedCode")

package scripts.exportClientDepGraphs

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
private val vulnClientsCollection = db.getCollection<BsonDocument>("mergedVulnClients")

private val clientGavs = vulnClientsCollection.find().useCursor { blk ->
    blk.map {
        it["client_gav"]!!.asString().value
    }
}.toSet()

private fun gavToJarUrl(packageGAV: String): String {
    val parts = packageGAV.split(":")
    return parts[0].replace('.', '/') + "/" + parts[1] + "/" + parts[2] + "/" + parts[1] + "-" + parts[2] + ".jar"
}

private val gavToJar = clientGavs.map {
    val jarPath = jarsDir.resolve(gavToJarUrl(it))
    if (!jarPath.isFile()) throw Exception("jar file not found")

    it to jarPath
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

private fun saveDepGraphInfo(
    classes: ClassInfoList,
    jGraph: DefaultGraph,
    gav: String?,
    scanResultAsJson: String,
) {
    val allOuterClasses = classes.filterNot { it.isInnerClass }.toSet()

    if (allOuterClasses.map { it.name }.toSet().intersect(jGraph.vertexSet()).size != jGraph.vertexSet().size) {
        throw Exception("vertex set size mismatch $gav")
    }

    dataDir
        .resolve("interim/depGraphCache.clients")
        .also { it.mkdirs() }
        .resolve("$gav.vertices.tsv.zip")
        .let { outFile ->
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

    dataDir.resolve("interim/depGraphCache.clients").also { it.mkdirs() }.resolve("$gav.edges.tsv.zip").let { outFile ->
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
        .resolve("interim/jarClassInfoCache.clients")
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

fun loadScanResultFromCache(gav: String): ScanResult {
    val outputJson = dataDir.resolve("interim/jarClassInfoCache.clients/$gav.scanResult.json.zip")
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
    val outputJson = dataDir.resolve("interim/jarClassInfoCache.clients/$gav.classInfo.json.zip")
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
    dataDir.resolve("interim/depGraphCache.clients/$gav.vertices.tsv.zip").let { vCache ->
        if (!vCache.isFile) throw FileNotFoundException("cache file not found ${vCache.absolutePath}")

        val eCache = dataDir.resolve("interim/depGraphCache.clients/$gav.edges.tsv.zip")
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
    dataDir.resolve("interim/depGraphCache.clients/$gav.vertices.tsv.zip").let { vCache ->
        if (!vCache.isFile) throw FileNotFoundException("cache file not found ${vCache.absolutePath}")

        val eCache = dataDir.resolve("interim/depGraphCache.clients/$gav.edges.tsv.zip")
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
                        loadDepGraphFromCache(it.key).let { }
                        loadVertexInfo(it.key).let { }
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