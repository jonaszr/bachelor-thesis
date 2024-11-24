#!/bin/bash
# call inside mongo container

# Import JSON metadata files
for file in *.json; do
  collection_name=$(basename "$file" .json | sed 's/.metadata//')
  mongoimport --db="s5_snyk_libio" --collection="$collection_name" --file="$file"
done
