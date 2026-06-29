#!/bin/bash

DEST=openapi/
VOSI=$HOME/work/dev/ivoa-std/VOSI.git

ARGS="$1 -avc --delete"

rsync $ARGS $VOSI/openapi/vosi openapi/

