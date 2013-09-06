#ifndef _LOG_PRINTER_STDIO_H
#define _LOG_PRINTER_STDIO_H

#include <stdbool.h>
#include <stdio.h>

#include "c_util.h"
#include "iface_util.h"
#include "logging_types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
log_printer_stdio_init(FILE *log_destination, bool show_colors);

bool
log_printer_stdio_default_init(void);

void
log_printer_stdio_shutdown(void);

PRINTF(4, 5) void
log_printer_stdio_print(const char *filename, int lineno,
                        log_level_t level,
                        const char *format, ...);

CREATE_IMPL_TAG(LOG_PRINTER_STDIO_IMPL);

#ifdef __cplusplus
}
#endif

#endif
