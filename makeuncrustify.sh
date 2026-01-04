#!/bin/sh

uncrustify -c uncrustify.cfg --replace --no-backup daemon/*.c daemon/*.h
