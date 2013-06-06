#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "watcher.h"

static int interrupted = 0;

struct watcher {
    HANDLE dir;
    HANDLE event;
    DWORD notify;
    BYTE buffer[32 * 1024];
    FILE_NOTIFY_INFORMATION *data;
    size_t next;
};

static BOOL WINAPI
signal_handler(DWORD type)
{
    interrupted = 1;
    return FALSE;
}

watcher_t *
watcher_init(void)
{
    watcher_t *self;

    self = (watcher_t *)malloc(sizeof(watcher_t));
    if (!self) {
        return NULL;
    }

    self->dir = NULL;
    self->event = NULL;
    self->notify = 0;
    memset(self->buffer, 0, sizeof(self->buffer));
    self->data = NULL;
    self->next = 0;

    return self;
}

void
watcher_destroy(watcher_t *self)
{
    if (self) {
        if (self->event) {
            CloseHandle(self->event);
        }
        if (self->dir) {
            CloseHandle(self->dir);
        }
        free(self);
    }
}

char *
watcher_error(void)
{
    return NULL;
}

int
watcher_recursively(watcher_t *self, char *dir)
{
    self->dir = CreateFile(dir, FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                           FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                           NULL);
    if (self->dir == INVALID_HANDLE_VALUE) {
        return -1;
    }

    self->notify = FILE_NOTIFY_CHANGE_FILE_NAME |
        FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_CREATION |
        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE;

    self->event = CreateEvent(NULL, TRUE, FALSE, NULL);

    return 0;
}

int
watcher_next_event(watcher_t *self)
{
    if (self->next == 0) {
        DWORD retval = 0;
        OVERLAPPED overlapped = {0};

        ResetEvent(self->event);

        overlapped.hEvent = self->event;

        SetConsoleCtrlHandler(signal_handler, TRUE);

        if (!ReadDirectoryChangesW(self->dir, self->buffer, sizeof(self->buffer),
                                   TRUE, self->notify, NULL, &overlapped,
                                   NULL)) {
            return -1;
        }

        while (!interrupted) {
            if (WaitForSingleObject(self->event, 500) != WAIT_TIMEOUT) {
                break;
            }
        }

        if (interrupted) {
            CancelIo(self->dir);
            WaitForSingleObject(self->event, INFINITE);
            return -1;
        }

        if (!GetOverlappedResult(self->dir, &overlapped, &retval, FALSE)) {
            return -1;
        }

        self->data = (FILE_NOTIFY_INFORMATION *)&self->buffer[0];
    } else {
        self->data = (FILE_NOTIFY_INFORMATION *)&self->buffer[self->next];
    }
    self->next = self->data->NextEntryOffset;

    return 0;
}

int
watcher_in_event(watcher_t *self)
{
    /*
    if (self->data) {
        switch (self->data->Action) {
            case FILE_ACTION_ADDED:
                break;
            case FILE_ACTION_REMOVED:
                break;
            case FILE_ACTION_MODIFIED:
                break;
            case FILE_ACTION_RENAMED_OLD_NAME:
                break;
            case FILE_ACTION_RENAMED_NEW_NAME:
                break;
        }
    }
    */
    return 0;
}

char *
watcher_get_filename(watcher_t *self)
{
    char *filename = NULL;
    DWORD len;
    int i, count;

    if (!self->data) {
        return NULL;
    }

    filename = (char *)malloc(self->data->FileNameLength + 2);
    if (!filename) {
        return NULL;
    }

    filename[0] = '/';

    len = self->data->FileNameLength / sizeof(WCHAR);
    count = WideCharToMultiByte(CP_ACP, 0, self->data->FileName,
                                len, &filename[1], self->data->FileNameLength,
                                NULL, NULL);
    filename[count+1] = '\0';

    for (i = 0; i <= count; i++) {
        if (filename[i] == '\\') {
            filename[i] = '/';
        }
    }

    return filename;
}
