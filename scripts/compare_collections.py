import os
from pymongo import MongoClient
from bson import ObjectId

db1_name = "s5_snyk_libio"
db2_name = "export_s5_snyk_libio"
collections = [
    "libioPackageVuln",
    "libioVuln",
    "mergedVuln",
    "mergedVulnClients",
    "mvnEcoVuln",
    "patchCommitsLibio",
    "patchUrls",
    "vulnUrlDetails",
    "vulnUrls",
]

# Specify which keys to use for finding matching entries for each collection
match_keys = {
    "libioExport": ["DependentName", "DependencyName", "DependentVersion",
                    "DependencyVersion", "DependentRepoName", "DependencyRepoName"],
    "libioPackageVuln": ["_id"],
    "libioVuln": ["cve_ref", "snyk_url", "vuln_gav"],
    "mergedVuln": ["cve_ref", "vuln_gav", "snyk_url"],
    "mergedVulnClients": ["cve", "dep_gav", "client_gav"],
    "mvnEcoVuln": ["cve_ref", "vuln_gav"],
    "packageVulnData": ["uuid"],
    "patchCommitsLibio": ["repo", "commitHash", "modifiedFilePathAfter", "snykPatchUrl"],
    "patchUrls": ["VulnUrl"],
    "vulnUrlDetails": ["VulnUrl"],
    "vulnUrls": ["DependencyName", "DependencyVersion"],
}

# Specify which keys to exclude from comparison for each collection
exclude_keys = {
    "libioPackageVuln": ["modifiedFileSrcBefore", "modifiedFileSrcAfter"],
}

output_folder = "comparison_results"
os.makedirs(output_folder, exist_ok=True)


def make_hashable(doc, keys):
    if isinstance(doc, dict):
        return tuple((k, make_hashable(v, keys)) for k, v in doc.items() if k in keys and not isinstance(v, ObjectId))
    elif isinstance(doc, list):
        return tuple(sorted(make_hashable(e, keys) for e in doc))
    else:
        # Convert all other types to string for consistent comparison
        return str(doc)


def make_comparable(doc, exclude_keys):
    if isinstance(doc, dict):
        return {
            k: make_comparable(v, exclude_keys)
            for k, v in doc.items()
            if k not in exclude_keys and not isinstance(v, ObjectId)
        }
    elif isinstance(doc, list):
        return sorted(
            (make_comparable(e, exclude_keys) for e in doc),
            key=lambda x: str(x)
        )
    else:
        return doc


def compare_collections(db1_name, db2_name, collection_name, host='localhost', port=42692):
    client = MongoClient(host, port)
    db1 = client[db1_name]
    db2 = client[db2_name]
    collection1 = db1[collection_name]
    collection2 = db2[collection_name]

    # Fetch all documents from both collections
    docs1 = list(collection1.find())
    docs2 = list(collection2.find())

    # Get the keys to use for matching and excluding from comparison
    keys_to_match = match_keys.get(collection_name, [])
    keys_to_exclude = exclude_keys.get(collection_name, [])

    # Create dictionaries to store documents by their match keys
    docs1_by_key = {}
    docs2_by_key = {}

    for doc in docs1:
        key = make_hashable(doc, keys_to_match)
        if key in docs1_by_key:
            docs1_by_key[key].append(doc)
        else:
            docs1_by_key[key] = [doc]

    for doc in docs2:
        key = make_hashable(doc, keys_to_match)
        if key in docs2_by_key:
            docs2_by_key[key].append(doc)
        else:
            docs2_by_key[key] = [doc]

    # Find differences
    only_in_collection1 = set(docs1_by_key.keys()) - set(docs2_by_key.keys())
    only_in_collection2 = set(docs2_by_key.keys()) - set(docs1_by_key.keys())
    common_keys = set(docs1_by_key.keys()) & set(docs2_by_key.keys())

    different_entries_count = 0
    multiple_matches_col1_count = 0
    multiple_matches_col2_count = 0

    output_file = os.path.join(
        output_folder, f"{collection_name}_comparison.txt")
    with open(output_file, "w") as f:
        f.write(f"Comparing {collection_name} in {db1_name} and {db2_name}\n")
        f.write(f"Total entries in {db1_name}: {len(docs1)}\n")
        f.write(f"Total entries in {db2_name}: {len(docs2)}\n")
        f.write("Entries only in collection 1:\n")
        for key in only_in_collection1:
            for entry in docs1_by_key[key]:
                f.write(f"{entry}\n")

        f.write("\nEntries only in collection 2:\n")
        for key in only_in_collection2:
            for entry in docs2_by_key[key]:
                f.write(f"{entry}\n")

        f.write("\nDifferent entries:\n")
        for key in common_keys:
            doc1 = docs1_by_key[key][0]
            doc2 = docs2_by_key[key][0]
            comparable_doc1 = make_comparable(doc1, keys_to_exclude)
            comparable_doc2 = make_comparable(doc2, keys_to_exclude)
            if comparable_doc1 != comparable_doc2:
                different_entries_count += 1
                f.write(f"Key: {key}\n")
                f.write(f"Collection 1 entry: {doc1}\n")
                f.write(f"Collection 2 entry: {doc2}\n")
                diff = {k: (comparable_doc1[k], comparable_doc2[k])
                        for k in comparable_doc1 if comparable_doc1[k] != comparable_doc2[k]}
                f.write(f"Diff: {diff}\n")
        f.write("\n" + "="*50 + "\n")

        f.write("\nMultiple matches found in collection 1:\n")
        for key in common_keys:
            if len(docs1_by_key[key]) > 1:
                multiple_matches_col1_count += 1
                f.write(f"Key: {key}\n")
                f.write(f"Collection 1 entries: {docs1_by_key[key]}\n")

        f.write("\nMultiple matches found in collection 2:\n")
        for key in common_keys:
            if len(docs2_by_key[key]) > 1:
                multiple_matches_col2_count += 1
                f.write(f"Key: {key}\n")
                f.write(f"Collection 2 entries: {docs2_by_key[key]}\n")

        f.write("\n" + "="*50 + "\n")

        matching_entries = len(common_keys)
        unique_in_collection1 = len(only_in_collection1)
        unique_in_collection2 = len(only_in_collection2)
        total_unique_entries = unique_in_collection1 + unique_in_collection2
        combined_entry_total = len(docs1) + len(docs2) - matching_entries
        matching_percentage = (
            matching_entries / combined_entry_total) * 100 if combined_entry_total > 0 else 0
        perfectly_matching_percentage = (
            (matching_entries - different_entries_count) / combined_entry_total) * 100 if combined_entry_total > 0 else 0

        f.write(
            f"Percentage of matching entries: {matching_percentage:.2f}%\n")
        f.write(
            f"Percentage of perfectly matching entries: {perfectly_matching_percentage:.2f}%\n")
        f.write(f"Combined total entries: {combined_entry_total}\n")
        f.write(f"Unique entries in collection 1: {unique_in_collection1}\n")
        f.write(f"Unique entries in collection 2: {unique_in_collection2}\n")
        f.write(f"Total unique entries: {total_unique_entries}\n")
        f.write(f"Matching entries: {matching_entries}\n")
        f.write(
            f"Matching entries with different comparisons: {different_entries_count}\n")
        f.write(f"Multiple matches in col1: {multiple_matches_col1_count}\n")
        f.write(f"Multiple matches in col2: {multiple_matches_col2_count}\n")

    summary_file = os.path.join(output_folder, "summary.txt")
    with open(summary_file, "a") as summary:
        summary.write(
            f"Compared {collection_name} in {db1_name} and {db2_name}\n")
        summary.write(f"Total entries in {db1_name}: {len(docs1)}\n")
        summary.write(f"Total entries in {db2_name}: {len(docs2)}\n")
        summary.write(f"Combined total entries: {combined_entry_total}\n")
        summary.write(
            f"Unique entries in collection 1: {unique_in_collection1}\n")
        summary.write(
            f"Unique entries in collection 2: {unique_in_collection2}\n")
        summary.write(f"Total unique entries: {total_unique_entries}\n")
        summary.write(f"Matching entries: {matching_entries}\n")
        summary.write(
            f"Matching entries with different comparisons: {different_entries_count}\n")
        summary.write(
            f"Percentage of matching entries: {matching_percentage:.2f}%\n")
        summary.write(
            f"Percentage of perfectly matching entries: {perfectly_matching_percentage:.2f}%\n")
        summary.write(
            f"Multiple matches in col1: {multiple_matches_col1_count}\n")
        summary.write(
            f"Multiple matches in col2: {multiple_matches_col2_count}\n")
        summary.write("="*50 + "\n")

    print(f"Compared {collection_name} in {db1_name} and {db2_name}")
    print(f"Total entries in {db1_name}: {len(docs1)}")
    print(f"Total entries in {db2_name}: {len(docs2)}")
    print(f"Combined total entries: {combined_entry_total}")
    print(f"Unique entries in collection 1: {unique_in_collection1}")
    print(f"Unique entries in collection 2: {unique_in_collection2}")
    print(f"Total unique entries: {total_unique_entries}")
    print(f"Matching entries: {matching_entries}")
    print(
        f"Matching entries with different comparisons: {different_entries_count}")
    print(f"Percentage of matching entries: {matching_percentage:.2f}%")
    print(
        f"Percentage of perfectly matching entries: {perfectly_matching_percentage:.2f}%")
    print(f"Multiple matches in col1: {multiple_matches_col1_count}")
    print(f"Multiple matches in col2: {multiple_matches_col2_count}")
    print("="*50)


if __name__ == "__main__":
    for collection in collections:
        compare_collections(db1_name, db2_name, collection)
