#! /bin/sh
#set -x
#
# $Id: autotools.sh 1194 2009-06-19 12:54:48Z vtschopp $
#

echo "Bootstrapping autotools..."

echo "aclocal..."
aclocal -I project
echo "libtoolize..."
libtoolize --force
echo "autoheader..."
autoheader
echo "automake..."
automake --foreign --add-missing --copy
echo "autoconf..."
autoconf

echo "Done."
