#!/bin/bash
export LC_ALL=C
set -e -o pipefail

. "$(dirname "$0")/project_root.sh"
require_project_root "contrib/scripts/run.sh"
