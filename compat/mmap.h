/** mmap() replacement for Windows
 *
 * Author: Mike Frysinger <vapier@gentoo.org>
 * Placed into the public domain
 */
#ifndef COMPAT_MMAP_H
#define COMPAT_MMAP_H

#if defined(__MINGW32__) || defined(_WIN32)
#include <sys/types.h>

#define PROT_READ     0x1
#define PROT_WRITE    0x2
/* This flag is only available in WinXP+ */
#ifdef FILE_MAP_EXECUTE
#define PROT_EXEC     0x4
#else
#define PROT_EXEC        0x0
#define FILE_MAP_EXECUTE 0
#endif

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS
#define MAP_FAILED    ((void *) -1)

void* mmap(void* start, size_t length, int prot, int flags, int fd, off_t offset);
void munmap(void* addr, size_t length);

#else
#include <sys/mman.h>
#endif

#endif
