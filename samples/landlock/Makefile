# SPDX-License-Identifier: BSD-3-Clause

userprogs-always-y := sandboxer

userccflags += -I usr/include
userldlibs += -lcap

.PHONY: all clean

all:
	$(MAKE) -C ../.. samples/landlock/

clean:
	$(MAKE) -C ../.. M=samples/landlock/ clean
