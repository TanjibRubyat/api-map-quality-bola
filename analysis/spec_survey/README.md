# Public specification survey (extension)

Scans the latest version of every API in the APIs.guru OpenAPI directory
(commit f04b8d0, 20 Apr 2026) for the documentation that the main experiment
removes. Only "object endpoints" are counted: GET operations whose path ends
with a `{placeholder}`, which are the endpoints where BOLA can occur.

    git clone --depth 1 --filter=blob:none --no-checkout https://github.com/APIs-guru/openapi-directory.git od
    cd od && git sparse-checkout init --no-cone
    sed 's#^#/#' ../analysis/spec_survey/spec_list.txt > .git/info/sparse-checkout
    git checkout f04b8d0 && cd ..
    python analysis/spec_survey/scan_public_specs.py od analysis/spec_survey/spec_list.txt results/extension/public_spec_survey

An id parameter counts as having an example if it has `example`, `examples`,
`x-example`, or a schema `example`, `examples` or `enum`. The owner-field check
is a name heuristic (ownerId, userId, accountId, createdBy, ...).
