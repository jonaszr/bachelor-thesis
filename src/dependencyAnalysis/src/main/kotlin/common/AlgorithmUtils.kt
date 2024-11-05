package common

import io.github.classgraph.ClassInfoList
import org.jbpt.algo.tree.mdt.MDT
import org.jbpt.graph.DirectedEdge
import org.jbpt.graph.DirectedGraph
import org.jbpt.hypergraph.abs.Vertex
import org.jgrapht.graph.AsSubgraph
import org.jgrapht.graph.DefaultEdge
import org.jgrapht.graph.builder.GraphTypeBuilder
import org.jgrapht.alg.connectivity.KosarajuStrongConnectivityInspector

internal fun MDT<DirectedEdge, Vertex>.toJGraph(): DefaultGraph {
    val vertices = this.vertices.map { v -> v.toString() }
    val edges = this.edges.map { e -> Pair(e.source.toString(), e.target.toString()) }

    val jGraph =
        GraphTypeBuilder
            .directed<String, DefaultEdge>()
            .allowingMultipleEdges(false)
            .allowingSelfLoops(false)
            .edgeClass(DefaultEdge::class.java)
            .weighted(true)
            .buildGraph()

    vertices.forEach { v -> jGraph.addVertex(v) }
    edges.forEach { e -> jGraph.addEdge(e.first, e.second) }

    return jGraph
}

internal fun DefaultGraph.toJbptGraph(): DirectedGraph {
    val directedGraph = DirectedGraph()

    val vertexMap = mapOf<String, Vertex>().toMutableMap()

    this.vertexSet().forEach { v ->
        val vertex = Vertex(v)
        vertexMap[v] = vertex
        directedGraph.addVertex(vertex)
    }

    this.edgeSet().forEach { e ->
        val sourceVertex = vertexMap[this.getEdgeSource(e)]
        val targetVertex = vertexMap[this.getEdgeTarget(e)]
        directedGraph.addEdge(sourceVertex, targetVertex)
    }

    return directedGraph
}

internal fun Map<String, Set<String>>.ungroup(): Map<String, String> {
    return this.flatMap { entry ->
        entry.value.map {
            it to entry.key
        }.toSet()
    }.toMap()
}

/** returns parent to children mapping */
internal fun Map<String, String>.group(): Map<String, Set<String>> {
    return this.asSequence().groupBy { it.value }.map { g -> g.key to g.value.map { it.key }.toSet() }.toMap()
}

/** returns child to grandparent mapping */
internal fun mergeRevMappings(
    parentToGrandparent: Map<String, String>,
    childToParent: Map<String, String>,
): Map<String, String> {
    return childToParent.asSequence().associate { (c, p) ->
        c to (parentToGrandparent[p]!!)
    }
}

/** return grandparent to children mappings */
internal fun mergeMappings(
    grandparentToParents: Map<String, Set<String>>,
    parentToChildren: Map<String, Set<String>>,
): Map<String, Set<String>> {
    return grandparentToParents.map { gp ->
        gp.key to gp.value.flatMap { p ->
            parentToChildren[p]!!
        }.toSet()
    }.toMap()
}

internal fun createSubGraphsBasedOnMappings(
    originalGraph: DefaultGraph,
    mapping: Map<String, Set<String>>,
): Map<String, DefaultGraph> {
    return mapping.map { cmg ->
        cmg.key to AsSubgraph(originalGraph, cmg.value)
    }.toMap()
}

// TODO use strategy
internal fun getSeedVertices(graph: DefaultGraph): Set<String> {
    return graph.vertexSet().filter { graph.inDegreeOf(it) == 0 }.toSet()
}

internal fun getMappingCardinalities(
    mapping: Map<String, Set<String>>,
): Map<String, Int> =
    mapping.map { it.key to it.value.size }.toMap()

/**
 * Gets a [DefaultGraph] and a condensation mapping [atomToCondensedNode] and returns the condensed graph.
 * @param originalGraph should be a weighted DAG without parallel edges and self loops.
 * @param atomToCondensedNode key is a node in the original graph and value is the node in the condensed graph.
 * @return the graph nodes are the keys in [atomToCondensedNode]
 */
internal fun createCondensedGraphFromMapping(
    originalGraph: DefaultGraph,
    atomToCondensedNode: Map<String, String>,
): DefaultGraph {
    val condensedGraph =
        GraphTypeBuilder
            .directed<String, DefaultEdge>()
            .allowingMultipleEdges(false)
            .allowingSelfLoops(false)
            .edgeClass(DefaultEdge::class.java)
            .weighted(true)
            .buildGraph()

    atomToCondensedNode.values.toSet().forEach {
        condensedGraph.addVertex(it)
    }

    originalGraph.edgeSet().forEach { e ->
        val source = atomToCondensedNode[originalGraph.getEdgeSource(e)]!!
        val target = atomToCondensedNode[originalGraph.getEdgeTarget(e)]!!

        if (source == target) return@forEach

        if (!condensedGraph.containsEdge(source, target)) {
            condensedGraph.addEdge(source, target)
        } else {
            val edge = condensedGraph.getEdge(source, target)
            val weight = condensedGraph.getEdgeWeight(edge)
            condensedGraph.setEdgeWeight(edge, weight + 1)
        }
    }

    return condensedGraph
}

/**
 * gets a list of [DefaultGraph]s and returns two mappings
 * @return (one random node from each graph -> nodes in that graph) and the reverse (node to the root node)
 */
internal fun createMappingsFromCondensations(graphSCCs: List<DefaultGraph>): Pair<Map<String, Set<String>>, Map<String, String>> {
    val condensationRootToVertexSet = graphSCCs.associate { con ->
        val rootVtx = con.vertexSet().first()
        val conVertices = con.vertexSet()
        rootVtx to conVertices
    }

    val vertexToCondensationRoot = condensationRootToVertexSet.flatMap {
        val conRoot = it.key
        val vertices = it.value
        vertices.map { v ->
            v to conRoot
        }
    }.toMap()

    return Pair(condensationRootToVertexSet, vertexToCondensationRoot)
}

// TODO: move to utils/common
fun ClassInfoList.toJGraph(
    collapseInnerClasses: Boolean = true,
): DefaultGraph {
    val graph =
        GraphTypeBuilder
            .directed<String, DefaultEdge>()
            .allowingMultipleEdges(false)
            .allowingSelfLoops(false)
            .edgeClass(DefaultEdge::class.java)
            .weighted(true)
            .buildGraph()

    val allClasses = this.map { it.name }.toSet()
    val allOuterClasses = allClasses.filterNot { it.contains("$") }.toSet()

    this.forEach { classInfo ->
        val source =
            (if (collapseInnerClasses) collapseInnerClass(classInfo.name, allOuterClasses) else classInfo.name)
                ?: return@forEach

        graph.addVertex(source)

        classInfo.classDependencies.forEach classDependencies@{ dependency ->
            val target =
                (if (collapseInnerClasses) collapseInnerClass(dependency.name, allOuterClasses) else dependency.name)
                    ?: return@classDependencies

            if (source == target) {
                return@classDependencies
            }

            graph.addVertex(target)

            if (graph.containsEdge(source, target)) {
                val edge = graph.getEdge(source, target)
                graph.setEdgeWeight(edge, graph.getEdgeWeight(edge) + 1)
            } else {
                graph.addEdge(source, target)
            }
        }
    }

    return graph
}

private fun collapseInnerClass(innerClassName: String, outerClasses: Set<String>) =
    innerClassName.substringBefore('$').let {
        if (it in outerClasses) {
            it
        } else {
            val it2 = it.trimEnd('_')
            if (it2 in outerClasses) {
                it2
            } else {
                null
            }
        }
    }

internal fun getGraphSCCs(graph: DefaultGraph): List<DefaultGraph> {
    return KosarajuStrongConnectivityInspector(graph).stronglyConnectedComponents
}