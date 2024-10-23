#pragma once
#include <unistd.h>
#define class(x)                                                               \
  typedef struct x x;                                                          \
  struct x
typedef struct CMrChrootHackPtrs {
  char *data_zone;
  char *pad;
} CMrChrootHackPtrs;
#define MR_CHROOT_NOSYS 281
class (CMountPoint) {
  CMountPoint *last, *next;
  char src_path[1024], dst_path[1024];
  char db_path[1024];
  char document_perms;
};
//May return NULL if the path is not to be documented
extern char *DatabasePathForFile(char *to, const char *path);
