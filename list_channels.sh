#!/bin/bash

for i in $(iwlist wlp2s0 scanning | grep Channel\: | sort | uniq) ; do echo ${i/Channel\:/ "" } ; done
