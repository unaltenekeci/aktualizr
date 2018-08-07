#! /bin/bash

set -exuo pipefail

export PATH=${PATH}/persistent

TMPDIR=$(mktemp)
create_repo.sh $TMPDIR 127.0.0.1
serve_repo.py 9000 $TMPDIR

aktualizr --config "${TMPDIR}/sota.toml"&

sleep 1

aktualizr-info --config "${TMPDIR}/sota.toml" | grep "Fetched metadata: yes" || exit 1

