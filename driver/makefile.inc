
driver.obj: src/driver.cpp
    $(CC) $(CFLAGS) src/driver.cpp

ldr.obj: src/ldr.cpp
    $(CC) $(CFLAGS) src/ldr.cpp

debug.obj: src/r0_common/debug.cpp
    $(CC) $(CFLAGS) src/r0_common/debug.cpp

common.obj: src/r0_common/common.cpp
    $(CC) $(CFLAGS) src/r0_common/common.cpp

LLIBS = ntoskrnl.lib hal.lib

LOBJS = driver.obj ldr.obj debug.obj common.obj
