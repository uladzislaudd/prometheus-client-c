#!/bin/bash

rm -rf .build && mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Release -DPROM_BUILD_TYPE=STATIC -DPROMHTTP_BUILD_TYPE=SHARED .. && make
