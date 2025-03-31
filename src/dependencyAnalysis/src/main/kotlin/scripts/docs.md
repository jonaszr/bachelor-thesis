- `exportDepGraphs`
    - `saveCaches`
        - computes the dependency graph from `mongo.mergedVuln`
        - saves vertices to `interim/depGraphCache/<gav>.vertices.tsv.zip`
        - saves edges to `interim/depGraphCache/<gav>.edges.tsv.zip`
        - saves classInfo (json) to `interim/depGraphCache/<gav>.classInfo.json.zip`
        - saves sccGraph to `interim/depGraphCache.scc/<gav>.dot`
            - saves mapping of vertex label (of scc roots) to numeric id to `interim/depGraphCache.scc/<gav>.v2id.tsv`
            - saves mapping of vertex label to scc root label to `interim/depGraphCache.scc/<gav>.v2r.tsv`
    - `checkCaches`
        - checks if it can load dependency graph caches for all records in `mongo.mergedVuln`

- `exportPairDepGraphs`
    - computes the dependency graph of pairs of <dep, client> from `mongo.mergedVulnClients`
    - saves vertices to `interimdepGraphCache.pairs/<depGav>#<clientGav>.vertices.tsv.zip`
    - saves edges to `interim/depGraphCache.pairs/<depGav>#<clientGav>.edges.tsv.zip`/
    - saves classInfo (json) to `interim/depGraphCache.pairs/<depGav>#<clientGav>.classInfo.json.zip`

- `partitionDepGraph.dagP`
  - computes dagP partitioning algorithm on dep graphs for gavs from `mongo.mergedVuln`
  - dagP is running on `interim/depGraphCache.scc/<gav>.dot`
  - dagP outputs multiple files but the one we care is `<gav>.dot.partsfile.part_<parts>.seed_<seed>.txt`
    - each row contains the partition number for each node
    - the node mappings are in the `.nodemapping` files, but they have the same order as our graph, so we don't care

- `modularityAlignment`
  - computes the modularity alignment (vs. namespaces in JARs) metrics and graphs
  - based on the `mongo.mergedVuln` collection
  - writes the outputs to `proc/modularityAlignment` directory
  - uses `interim/modularityAlignment` as cache (for frequent runs)
