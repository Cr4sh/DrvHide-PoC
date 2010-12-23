extern "C"
{
#include <ntddk.h>
#include <stdio.h>
#include <stdarg.h>
#include <ntddscsi.h>
#include <srb.h>
#include "r0_common/undocnt.h"
}

#define WP_STUFF

#include "r0_common/pe.h"
#include "r0_common/common.h"
#include "r0_common/debug.h"
#include "ldr.h"
