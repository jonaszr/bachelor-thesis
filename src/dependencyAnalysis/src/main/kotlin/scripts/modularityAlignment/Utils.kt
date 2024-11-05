package scripts.modularityAlignment

import common.DefaultGraph
import io.github.classgraph.ClassInfoList

fun loadDepGraph(gav: String): DefaultGraph =
    scripts.exportDepGraphs.loadDepGraphFromCache(gav)

fun loadClassListInfo(gav: String): ClassInfoList =
    scripts.exportDepGraphs.loadClassInfoListFromCache(gav)

fun loadVertexInfo(gav: String) =
    scripts.exportDepGraphs.loadVertexInfo(gav)

fun loadDepGraph(depGav: String, clientGav: String): DefaultGraph =
    scripts.exportPairDepGraphs.loadDepGraphFromCache(depGav, clientGav)

fun loadClassListInfo(depGav: String, clientGav: String): ClassInfoList =
    scripts.exportPairDepGraphs.loadClassInfoListFromCache(depGav, clientGav)

fun loadVertexInfo(depGav: String, clientGav: String) =
    scripts.exportPairDepGraphs.loadVertexInfo(depGav, clientGav)