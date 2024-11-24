#!/bin/bash
# call inside mongo container

# Restore BSON files
for file in *.bson; do
  collection_name=$(basename "$file" .bson)
  mongorestore --db="s5_snyk_libio" --collection="$collection_name" --drop "$file"
done
