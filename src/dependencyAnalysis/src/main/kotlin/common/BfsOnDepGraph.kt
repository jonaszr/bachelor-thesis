package common

import com.google.common.collect.Queues
import kotlin.math.min

/**
 * returns the depths of each visited node from the starting node
 */
fun bfsOnDepGraph(graph: DefaultGraph, startNode: String): Map<String, Int> {
    val expanded = mutableSetOf<String>()
    val depthMap = mutableMapOf<String, Int>()
    val queue = Queues.newArrayDeque<String>()
    queue.add(startNode)
    depthMap[startNode] = 0
    while (!queue.isEmpty()) {
        val node = queue.pop()
        expanded.add(node)
        val parentDepth = depthMap[node]!!
        graph.outgoingEdgesOf(node).map { e -> graph.getEdgeTarget(e) }.filterNot { expanded.contains(it) }.forEach { v ->
                if (depthMap.containsKey(v)) {
                    depthMap[v] = min(depthMap[v]!!, parentDepth + 1)
                } else {
                    depthMap[v] = parentDepth + 1;
                }
                queue.add(v)
            }
    }
    return depthMap
}

fun addFakeSourceToNodes(graph: DefaultGraph, startingNodes: Set<String>, fakeNode: String) {
    graph.addVertex(fakeNode)
    startingNodes.forEach { v ->
        graph.addEdge(fakeNode, v)
    }
}