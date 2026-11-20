# Public specification survey (extension)

Reads the latest specification of every API in the APIs.guru OpenAPI directory
(commit f04b8d0, 20 Apr 2026) for the documentation that the main experiment
removes.
It only reads the published files and sends no request to any API. Only "object endpoints" are counted: GET operations whose path ends
with a `{placeholder}`, which are the endpoints where BOLA can occur.

Run these commands in Git Bash (on Windows) or any Unix shell, from the project folder.
The clone downloads file names only, and the checkout then downloads the 2,658
chosen files (about 600 MB).

    git clone --filter=blob:none --no-checkout https://github.com/APIs-guru/openapi-directory.git od
    cd od
    git ls-tree -r --name-only f04b8d0 | grep -E '(openapi|swagger)\.(yaml|json)$' > ../all.txt
    python ../analysis/spec_survey/pick_latest.py ../all.txt ../analysis/spec_survey/spec_list.txt
    git sparse-checkout init --no-cone
    sed 's#^#/#' ../analysis/spec_survey/spec_list.txt > .git/info/sparse-checkout
    git checkout f04b8d0 && cd ..
    python analysis/spec_survey/scan_public_specs.py od analysis/spec_survey/spec_list.txt results/extension/public_spec_survey

An id parameter counts as having an example if it has `example`, `examples`,
`x-example`, or a schema `example`, `examples` or `enum`. The owner-field check
is a name heuristic (ownerId, userId, accountId, createdBy, ...).
