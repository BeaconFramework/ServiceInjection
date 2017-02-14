#/bin/sh

ORIG_DIR=$HOME/sflowtool/orig/sflowtool-3.35
NEW_DIR=$HOME/sflowtool/new/sflowtool-3.35

echo "Create patch of sflowtool"
diff -u $ORIG_DIR/src/sflowtool.c $NEW_DIR/src/sflowtool.c > sflowtool.patch
