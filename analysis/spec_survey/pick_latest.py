r"""Choose the latest version of each API in the APIs.guru directory.

Input:  a list of every spec path in the repository, for example from
        git ls-tree -r --name-only HEAD | grep -E '(openapi|swagger)\.(yaml|json)$' > all.txt
Output: one path per API (the highest version number), written to spec_list.txt.

Paths look like APIs/<provider>[/<service>]/<version>/openapi.yaml, so the API is
everything before the version folder, and versions are compared by their numbers.
"""
import re
import sys
from collections import defaultdict


def version_key(path):
    numbers = re.findall(r"\d+", path.split("/")[-2])
    return tuple(int(n) for n in numbers) if numbers else (-1,)


def main(all_paths_file, out_file):
    groups = defaultdict(list)
    for path in open(all_paths_file, encoding="utf-8").read().splitlines():
        groups["/".join(path.split("/")[:-2])].append(path)
    picked = [max(paths, key=version_key) for paths in groups.values()]
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(picked))
    print(f"{len(groups)} APIs, {len(picked)} specs written to {out_file}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
