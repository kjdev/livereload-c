#ifndef __WATCHER_H__
#define __WATCHER_H__

typedef struct watcher watcher_t;

watcher_t * watcher_init(void);
void watcher_destroy(watcher_t *self);
char * watcher_error(void);
int watcher_recursively(watcher_t *self, char *dir);
int watcher_next_event(watcher_t *self);
int watcher_in_event(watcher_t *self);
char * watcher_get_filename(watcher_t *self);

#endif
