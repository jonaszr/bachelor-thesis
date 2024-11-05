### data pipeline

#### data preparation

- `libioSnyk*`
  - data stemming from libraries.io + security.snyk.io
  - the data is previously exported to mongodb
    - summary: lib info and patch commits for java libs from libraries.io that have a GitHub repo and recorded vulnerability in snyk vulnerability database
- `libioSnyk`
  - clone repos and find modified java files in patch commits
  - add to `libioSnyk`
- `libioSnyk.modifiedClasses`
  - use java parser to get the top-level package+class for each modified file
  - modify `libioSnyk`
- `libioSnyk.flatten`
  - simple reformatting
  - add to `libioVuln`
- `libioSnyk.dlJars`
  - download the jars of gavs listed in `libioVuln`
  - save to `interim/jars`
- `libioSnyk.filterMatches`
  - keep items that have jars
  - keep `vuln_classes` that actually exist in the jar
  - keep items that have at least one `vuln_classes`
  - modify (rm rows) `libioVuln`


- `mvnEco*`
  - data stemming from project [Understanding the Threats of Upstream Vulnerabilities to Downstream Projects in the Maven Ecosystem](https://dl.acm.org/doi/abs/10.1109/ICSE48619.2023.00095)
- `mvnEco.import`
  - import the data from CSVs in the repo
  - add to `mvnEcoVuln`
- `mvnEco.dlJars`
  - download the jars of gavs listed in `mvnEcoVuln`
  - save to `inteirm/jars`
- `mvnEco.filterMatches`
  - keep items that have jars
  - keep `vuln_classes` that actually exist in the jar
  - keep items that have at least one `vuln_classes`
  - modify (rm rows) `mvnEcoVuln`


- `merge`
  - merges `libioVuln` and `mvnEcoVuln`
  - add all from `libioVuln`
  - add rows from `mvnEcoVuln` not in `libioVuln`
  - add to `mergedVuln`
- `merged.clients`
  - merge the client libraries from previous datasets
  - randomly choose single record per unique `cve, dependency, client` 
  - add to `mergedVulnClients`
- `merged.clients.dlJars`
  - download the jars of gavs listed in `mergedVulnClients`
  - save to `inteirm/jars`