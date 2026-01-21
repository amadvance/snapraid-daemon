#!/bin/sh

uncrustify -c uncrustify.cfg --replace --no-backup daemon/*.c daemon/*.h

sed -i 's/[[:blank:]]*$//' snapraidd.conf
sed -i 's/[[:blank:]]*$//' snapraidd.yaml
