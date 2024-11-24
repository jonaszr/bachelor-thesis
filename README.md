[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.13381698.svg)](https://zenodo.org/doi/10.5281/zenodo.13381698)


This is the replication package for [Enhancing Security through Modularization: A Counterfactual Analysis of Vulnerability Propagation and Detection Precision](https://conf.researchr.org/details/scam-2024/SCAM-2024-research-track/13/Enhancing-Security-through-Modularization-A-Counterfactual-Analysis-of-Vulnerability)


The source code is available under `src`.

The data is available under `data.tgz`.

To start:
- Extract `data.tgz`.
- Follow the readme under the extracted directory
    - Create a mongodb instance using the exported db.
    - Download the jars using `aria2`
    - Create the caches by running the scripts described in `src/dependencyAnalysis/src/main/kotlin/scripts/docs.md`
- To run most scripts/notebooks you need to create a `.env` file in the same directory as the notebook (or the process working directory of the starting process for non-notebook files) containing the necessary variables
  - `DATA_DIR` should refer to the extracted data directory
  - `DAGP_EXE` should refer to the directory containing the executables (refer to the [original repo](https://github.com/GT-TDAlab/dagP) for more info)
  - `MVN_ECO_DIR` should refer to the replication repository of [Understanding the Threats of Upstream Vulnerabilities to Downstream Projects in the Maven Ecosystem](https://dl.acm.org/doi/abs/10.1109/ICSE48619.2023.00095)
  - `LOG_DIR` should refer to any directory that should be used to save the logs (optional)
- To run dagP, you need to use the patched version that is included in this repo (compile if necessary)
- We patched the classgraph library to fix multiple bugs. You need to install the patched version of this library into your local repo.
- For more details on data collection, data cleaning and answering the RQs refer to the notebooks under `src/dependencyAnalysis/src/main/notebooks`
- Please read any code before running it. Most likely you need to do small modifications to get what you need.

Set values in projects .env

docker-compose
  -mongo
    - Running on port 42692
  -mongo_express
    - Running on port 8081
    - http://0.0.0.0:8081
    - credentials: admin:pass