# %%
import com.mongodb.client.*
import org.litote.kmongo.*
import org.bson.BsonDocument
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import com.google.common.hash.Hashing

# %%
import io.github.cdimascio.dotenv.Dotenv
import java.nio.file.Paths

val dotenv = Dotenv.load()
val dataDir = dotenv.get("DATA_DIR").let {Paths.get(it).toFile()}.also {it.mkdirs()}
dataDir

# %%

val client = KMongo.createClient("mongodb://localhost:42692/")
val db = client.getDatabase("s5_snyk_libio")
val libioVuln = db.getCollection < BsonDocument > ("libioVuln")

# %%

private class MongoCursorIterable < T > (private val cursor: MongoCursor < T > ) : MongoCursor < T > by cursor, Iterable < T > {

    override fun iterator(): Iterator < T > = cursor
}

private fun < T > MongoIterable < T > .kCursor(): MongoCursorIterable < T > = MongoCursorIterable(iterator())

fun < T, R > MongoIterable < T > .useCursor(block: (Iterable < T > ) -> R): R {
    return kCursor().use(block)
}

# %%
val vulnGavs = libioVuln.find().useCursor {blk ->
                                           blk.map {
                                               it["vuln_gav"]!!.asString().value
                                           }
                                           }.toSet()

vulnGavs.count()

# %%
val jarsDir = dataDir.resolve("interim/jars").also {it.mkdirs()}

fun gavToJarUrl(packageGAV: String): String
{
    val parts = packageGAV.split(":")
    return parts[0].replace('.', '/') + "/" + parts[1] + "/" + parts[2] + "/" + parts[1] + "-" + parts[2] + ".jar"
}

# %%
fun _aria2cDlTxt(repoUrl: String) =
vulnGavs.map {
    val jarUrl = gavToJarUrl(it)
    val jarPath = jarsDir.resolve(jarUrl).also {it.parentFile.mkdirs()}.relativeTo(jarsDir).path
    val dlUrl = "$repoUrl/$jarUrl"
    "$dlUrl\n\tout=$jarPath"
}.joinToString("\n")

// val aria2DlTxtMvn = _aria2cDlTxt("https://repo1.maven.org/maven2")
val aria2DlTxtMvn = _aria2cDlTxt("https://repo.jenkins-ci.org/releases")
// DISPLAY(aria2DlTxtMvn)
jarsDir.resolve("dl.txt").writeText(aria2DlTxtMvn)

# %% [markdown]
# now run aria2c

# %%
val gavToJar = vulnGavs
.map {
    val jarPath = jarsDir.resolve(gavToJarUrl(it))
    if (!jarPath.isFile()) null
    else it to jarPath.relativeTo(dataDir).path
}
.filterNotNull()
.toMap()
gavToJar.count()

# %%
gavToJar.asSequence().shuffled().first()
