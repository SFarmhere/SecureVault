#!/bin/bash
find . -type d -empty -not -path "*/\.*" -exec touch {}/.gitkeep \;