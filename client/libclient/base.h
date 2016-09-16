#pragma once

#ifndef ARRAY_COUNT
#define ARRAY_COUNT(x) ((sizeof(x))/sizeof(x[0]))
#endif

#ifndef UNUSED
#define UNUSED(x) (void)x
#endif