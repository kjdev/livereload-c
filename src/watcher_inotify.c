#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <inotifytools/inotifytools.h>
#include <inotifytools/inotify.h>

#include "watcher.h"

struct watcher {
    int inotify;
    struct inotify_event *event;
    size_t offset;
};

watcher_t *
watcher_init(void)
{
    watcher_t *self;

    self = (watcher_t *)malloc(sizeof(watcher_t));
    if (!self) {
        return NULL;
    }

    self->inotify = inotifytools_initialize();
    if (!self->inotify) {
        free(self);
        return NULL;
    }
    self->event = NULL;
    self->offset = 0;

    inotifytools_set_printf_timefmt("%H:%M:%S");

    return self;
}

void
watcher_destroy(watcher_t *self)
{
    if (self) {
        if (self->inotify) {
            inotifytools_cleanup();
        }
        free(self);
    }
}

char *
watcher_error(void)
{
    return strerror(inotifytools_error());
}

int
watcher_recursively(watcher_t *self, char *dir)
{
    int i;

    //if (!inotifytools_watch_recursively(dir, IN_ALL_EVENTS)) {
    if (!inotifytools_watch_recursively(dir,
                                        IN_CLOSE_WRITE|IN_DELETE|IN_MODIFY)) {
        return -1;
    }

    self->offset = strlen(dir);

    for (i = self->offset - 1; i >= 0; i--) {
        if (dir[i] != '/') {
            break;
        }
        self->offset--;
    }

    return 0;
}

int
watcher_next_event(watcher_t *self)
{
    self->event = inotifytools_next_event(-1);
    if (!self->event) {
        return -1;
    }

    return 0;
}

int
watcher_in_event(watcher_t *self)
{
    if (self->event &&
        (self->event->mask == IN_CLOSE_WRITE ||
         self->event->mask == IN_DELETE ||
         self->event->mask == IN_MODIFY)) {
        return 0;
    }
    return -1;
}

char *
watcher_get_filename(watcher_t *self)
{
    char *str, *path, *file, *filename = NULL;
    size_t len;

    if (!self->event || !self->event->name) {
        return NULL;
    }

    path = inotifytools_filename_from_wd(self->event->wd) + self->offset;
    file = self->event->name;

    len = strlen(path) + strlen(file) + 1;
    filename = (char *)malloc(len * sizeof(char));
    if (!filename) {
        return NULL;
    }

    memset(filename, 0, len);

    str = strcat(filename, path);
    str = strcat(str, file);

    return filename;
}
