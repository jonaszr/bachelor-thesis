@file:Suppress("DuplicatedCode")

package scripts.exportPairDepGraphs

import common.toJGraph
import io.github.cdimascio.dotenv.Dotenv
import io.github.classgraph.ClassGraph
import io.github.classgraph.ClassInfoList
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
import java.net.URLClassLoader
import java.nio.file.Paths
import kotlin.time.measureTime

class Main

val dotenv = Dotenv.load()
val dataDir = dotenv.get("DATA_DIR").let { Paths.get(it).toFile() }.also { it.mkdirs() }
val jarsDir = dataDir.resolve("interim/jars").also { it.mkdirs() }

val client = KMongo.createClient("mongodb://localhost:42692/")
val db = client.getDatabase("s5_snyk_libio")
val vulnCollection = db.getCollection<BsonDocument>("mergedVulnClients")

val vulnGavPairs = vulnCollection.find().useCursor { blk ->
    blk.map {
        val depGav = it["dep_gav"]!!.asString().value
        val clientGav = it["client_gav"]!!.asString().value
        depGav to clientGav
    }
}.toSet()

fun gavToJarUrl(packageGAV: String): String {
    val parts = packageGAV.split(":")
    return parts[0].replace('.', '/') + "/" + parts[1] + "/" + parts[2] + "/" + parts[1] + "-" + parts[2] + ".jar"
}

val gavToJar = vulnGavPairs.flatMap {
    sequence {
        yield(it.first)
        yield(it.second)
    }
}.associateWith {
    val jarPath = jarsDir.resolve(gavToJarUrl(it))
    if (!jarPath.isFile()) {
        error("jar file not found ${jarPath.absolutePath}")
    }

    jarPath
}

fun loadJarIntoClassPath(jar: File): URLClassLoader =
    URLClassLoader(arrayOf(jar.toURI().toURL()))

fun loadJarsIntoClassPath(vararg jars: File): URLClassLoader =
    URLClassLoader(jars.map { it.toURI().toURL() }.toTypedArray())

val dispatcher = Dispatchers.IO.limitedParallelism(16)

fun saveCaches() =
    runBlocking {
        vulnGavPairs.asSequence().windowed(512, 512, true).forEach { w ->
            System.gc()
            w.map {
                async(dispatcher) {
                    // if (it != "commons-fileupload:commons-fileupload:1.3.1" to "org.dihedron.strutlets:strutlets:1.0.6") {
                    //     return@async
                    // }

                    val (depGav, clientGav) = it
                    val depJar = gavToJar[depGav]!!
                    val clientJar = gavToJar[clientGav]!!

                    val (scanResultAsJson, jGraph, classes) =
                        // try {
                        loadJarsIntoClassPath(
                            depJar, clientJar
                        ).use { classLoader ->
                            ClassGraph()
                                .also { it.overrideClassLoaders(classLoader) }
                                .enableInterClassDependencies()
                                .enableAllInfo()
                                .acceptJars(depJar.name, clientJar.name)
                                .scan()
                                .use { scanResult ->
                                    val analyzerPath =
                                        File(Main::class.java.protectionDomain.codeSource.location.toURI()).canonicalPath
                                    val classes = ClassInfoList(scanResult.allClasses.filter { it2 ->
                                        it2 != null && it2.classpathElementFile != null && !it2.classpathElementFile.canonicalPath.contains(
                                            analyzerPath
                                        )
                                    }.filterNot { it2 -> it2.isExternalClass })

                                    val jGraph = classes.toJGraph(collapseInnerClasses = true)

                                    Triple(
                                        JSONSerializer.serializeObject(classes, 2, false), jGraph, classes
                                    )
                                }
                        }

                    // } catch (e: Exception) {
                    //     println("$it")
                    //     throw e;
                    // }

                    // note: after debugging one case, I figured that ClassGraph's implementation of isInnerClass is
                    // not accurate (i.e., there are some classes that are actually outer class but are marked as
                    // inner class by ClassGraph)
                    // val allOuterClasses = classes.filterNot { it.isInnerClass }.toSet() // buggy! TODO: report
                    // val allOuterClasses = classes.filter { jGraph.vertexSet().contains(it.name) }.toSet()

                    // dataDir
                    //     .resolve("interim/depGraphCache.pairs")
                    //     .also { it.mkdirs() }
                    //     .resolve("$depGav#$clientGav.vertices.tsv.zip")
                    //     .let { outFile ->
                    //         allOuterClasses.joinToString("\n") { v ->
                    //             "${v.name}\t${v.modifiers}"
                    //         }.byteInputStream().use { inStream ->
                    //             FileOutputStream(outFile).use { outFile ->
                    //                 CompressorStreamFactory()
                    //                     .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, outFile)
                    //                     .use { zipOut ->
                    //                         inStream.copyTo(zipOut)
                    //                     }
                    //             }
                    //         }
                    //     }
                    //
                    // dataDir
                    //     .resolve("interim/depGraphCache.pairs")
                    //     .also { it.mkdirs() }
                    //     .resolve("$depGav#$clientGav.edges.tsv.zip")
                    //     .let { outFile ->
                    //         jGraph.edgeSet().joinToString("\n") { e ->
                    //             "${jGraph.getEdgeSource(e)}\t${jGraph.getEdgeTarget(e)}"
                    //         }.byteInputStream().use { inStream ->
                    //             FileOutputStream(outFile).use { outFile ->
                    //                 CompressorStreamFactory()
                    //                     .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, outFile)
                    //                     .use { zipOut ->
                    //                         inStream.copyTo(zipOut)
                    //                     }
                    //             }
                    //         }
                    //     }
                    //
                    // dataDir
                    //     .resolve("interim/jarClassInfoCache")
                    //     .also { it.mkdirs() }
                    //     .resolve("$depGav#$clientGav.classInfo.json.zip")
                    //     .let { outFile ->
                    //         scanResultAsJson.byteInputStream().use { inStream ->
                    //             FileOutputStream(outFile).use { outFile ->
                    //                 CompressorStreamFactory()
                    //                     .createCompressorOutputStream(CompressorStreamFactory.DEFLATE, outFile)
                    //                     .use { zipOut ->
                    //                         inStream.copyTo(zipOut)
                    //                     }
                    //             }
                    //         }
                    //     }
                }
            }.toList().awaitAll()
        }
    }

fun loadClassInfoListFromCache(depGav: String, clientGav: String): ClassInfoList {
    val outputJson = dataDir.resolve("interim/jarClassInfoCache.pairs/$depGav#$clientGav.json.zip")
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

fun loadDepGraphFromCache(depGav: String, clientGav: String) =
    dataDir
        .resolve("interim/depGraphCache.pairs/$depGav#$clientGav.vertices.tsv.zip")
        .let { vCache ->
            if (!vCache.isFile) throw FileNotFoundException("cache file not found ${vCache.absolutePath}")

            val eCache = dataDir.resolve(
                "interim/depGraphCache.pairs/$depGav#$clientGav.edges.tsv.zip"
            )
            if (!eCache.isFile) throw FileNotFoundException("cache file not found ${eCache.absolutePath}")
            val g =
                GraphTypeBuilder
                    .directed<String, DefaultEdge>()
                    .allowingMultipleEdges(false)
                    .allowingSelfLoops(false)
                    .edgeClass(DefaultEdge::class.java)
                    .weighted(true)
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

fun loadVertexInfo(depGav: String, clientGav: String) =
    dataDir
        .resolve("interim/depGraphCache.pairs/$depGav#$clientGav.vertices.tsv.zip")
        .let { vCache ->
            if (!vCache.isFile) throw FileNotFoundException("cache file not found ${vCache.absolutePath}")

            val eCache =
                dataDir.resolve("interim/depGraphCache.pairs/$depGav#$clientGav.edges.tsv.zip")
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

fun checkCaches() {
    val dispatcher = Dispatchers.IO.limitedParallelism(64)

    vulnGavPairs.toSet().asSequence().windowed(512, 512, true).forEach { w ->
        System.gc()
        runBlocking {
            w.map {
                async(dispatcher) {
                    try {
                        // loadClassInfoListFromCache(it.first, it.second) // 1339 seconds for 45.7k items
                        val g = loadDepGraphFromCache(it.first, it.second)  // 235 seconds for 45.7k items
                        // loadVertexInfo(it.first, it.second)
                    } catch (e: FileNotFoundException) {
                        println("file not found $it ${e.message}")
                    } catch (e: Exception) {
                        println("error $it ${e.message} ${e.stackTraceToString()}")
                    }
                }
            }.toList().awaitAll().toList()
        }
    }
}

fun main() {
    println(vulnGavPairs.toSet().size)

    val t = measureTime {
        // saveCaches()
        checkCaches()
    }

    println("it took ${t / 1000} seconds")
}