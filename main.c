#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <time.h>

#include <mpv/client.h>
#include <zlib.h>
#include <png.h>
#include <xcb/xcb.h>
#include <xcb/xproto.h>

#define INITIAL_ALLOC (sizeof(uint8_t) * 1024 * 1024)

static xcb_atom_t TARGETS;
static xcb_atom_t ATOM;

static xcb_atom_t clipboard;
static xcb_atom_t prop;
static xcb_atom_t png_target;

static xcb_window_t holder;
static pthread_cond_t prop_cond;
static pthread_mutex_t prop_mutex;
static xcb_timestamp_t prop_ts;
static int fired;

static pthread_mutex_t shot_mutex;
static struct png_shot_buffer shot_data;
static int shot_used;

struct png_shot_buffer
{
    uint8_t *data;
    size_t current_size;
    size_t written;
};

mpv_node *get_map_value(mpv_node_list *map, const char *key)
{
    mpv_node *result = NULL;
    for (int i = 0; i < map->num; i++)
    {
        if (strcmp(key, map->keys[i]) == 0)
        {
            result = &map->values[i];
        }
    }
    return result;
}

void user_write_data(png_structp png_ptr, png_bytep data, png_size_t length)
{
    struct png_shot_buffer *result = png_get_io_ptr(png_ptr);
    size_t new_size = result->written + length;
    if (new_size > result->current_size)
    {
        size_t realloc_size = result->current_size * 1.5;
        result->data = realloc(result->data, realloc_size);
        result->current_size = realloc_size;
    }
    memcpy(result->data + result->written, data, length);
    result->written = new_size;
}

void user_flush_data(png_structp _)
{
    return;
}

void convert_to_png(int64_t w, int64_t h, int64_t stride, const uint8_t *mpv_data, struct png_shot_buffer *result)
{
    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr)
    {
        printf("[clipshot] failed to create png struct");
        return;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr)
    {
        printf("[clipshot] failed to create png info struct");
        png_destroy_write_struct(&png_ptr, (png_infopp)NULL);
        return;
    }

    result->data = malloc(INITIAL_ALLOC);
    result->current_size = INITIAL_ALLOC;
    result->written = 0;

    const uint8_t **row_pointers = malloc(sizeof(uint8_t *) * h);
    for (int i = 0; i < h; i++)
    {
        row_pointers[i] = mpv_data + stride * i;
    }

    if (setjmp(png_jmpbuf(png_ptr)))
    {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        free(row_pointers);
        if (result->data != NULL)
        {
            free(result->data);
        }
        return;
    }

    png_set_write_fn(png_ptr, result, user_write_data, user_flush_data);

    png_set_compression_level(png_ptr, 6);
    png_set_IHDR(png_ptr, info_ptr, w, h, 8,
                 PNG_COLOR_TYPE_RGBA,
                 PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT,
                 PNG_FILTER_TYPE_DEFAULT);

    png_set_bgr(png_ptr);
    png_set_rows(png_ptr, info_ptr, row_pointers);
    png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_STRIP_ALPHA | PNG_TRANSFORM_INVERT_ALPHA, NULL);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    free(row_pointers);
}

void handle_x_events(xcb_connection_t *conn)
{
    while (1)
    {
        xcb_generic_event_t *event = xcb_wait_for_event(conn);
        if (event == NULL)
        {
            int err = xcb_connection_has_error(conn);
            if (err > 0)
            {
                printf("[clipshot] x connection error: %d\n", err);
                return;
            }
            else
            {
                continue;
            }
        }
        switch (event->response_type & ~0x80)
        {
        case XCB_SELECTION_REQUEST:
        {
            xcb_selection_request_event_t *e = (xcb_selection_request_event_t *)event;

            xcb_get_atom_name_cookie_t pcook = xcb_get_atom_name(conn, e->property);
            xcb_get_atom_name_cookie_t tcook = xcb_get_atom_name(conn, e->target);
            xcb_get_atom_name_reply_t *prep = xcb_get_atom_name_reply(conn, pcook, NULL);
            xcb_get_atom_name_reply_t *trep = xcb_get_atom_name_reply(conn, tcook, NULL);

            /*
            printf("[clipshot] got selection request, requestor: %" PRIu32 ", property: %" PRIu32 " (%.*s), target: %" PRIu32 "(%.*s)\n",
                   e->requestor,
                   e->property, xcb_get_atom_name_name_length(prep), xcb_get_atom_name_name(prep),
                   e->target, xcb_get_atom_name_name_length(trep), xcb_get_atom_name_name(trep));
            */

            xcb_selection_notify_event_t *notify_event = calloc(1, 32);
            notify_event->response_type = XCB_SELECTION_NOTIFY;
            notify_event->requestor = e->requestor;
            notify_event->selection = e->selection;
            notify_event->target = e->target;
            notify_event->time = e->time;

            if (e->target == TARGETS)
            {
                xcb_change_property(conn, XCB_PROP_MODE_REPLACE, e->requestor, e->property, ATOM, 32, 1, &png_target);
                notify_event->property = e->property;
                xcb_send_event(conn, 0, e->requestor, XCB_EVENT_MASK_NO_EVENT, (char *)notify_event);
                xcb_flush(conn);
            }
            else if (e->target == png_target)
            {
                struct png_shot_buffer data;
                pthread_mutex_lock(&shot_mutex);
                data = shot_data;
                shot_used = 1;
                pthread_mutex_unlock(&shot_mutex);

                xcb_change_property(conn, XCB_PROP_MODE_REPLACE, e->requestor, e->property, png_target, 8, data.written, data.data);
                notify_event->property = e->property;
                xcb_send_event(conn, 0, e->requestor, XCB_EVENT_MASK_NO_EVENT, (char *)notify_event);
                xcb_flush(conn);

                pthread_mutex_lock(&shot_mutex);
                if (shot_data.data != data.data)
                {
                    free(data.data);
                }
                pthread_mutex_unlock(&shot_mutex);
            }
            else
            {
                notify_event->property = XCB_NONE;
                xcb_send_event(conn, 0, e->requestor, XCB_EVENT_MASK_NO_EVENT, (char *)notify_event);
                xcb_flush(conn);
            }

            free(notify_event);
            break;
        }
        case XCB_PROPERTY_NOTIFY:
        {
            xcb_property_notify_event_t *e = (xcb_property_notify_event_t *)event;
            if (e->window != holder || e->atom != prop)
            {
                continue;
            }
            pthread_mutex_lock(&prop_mutex);
            prop_ts = e->time;
            fired = 1;
            pthread_cond_signal(&prop_cond);
            pthread_mutex_unlock(&prop_mutex);
            break;
        }
        }
    }
}

int mpv_open_cplugin(mpv_handle *handle)
{
    fired = 0;

    int err = pthread_cond_init(&prop_cond, NULL);
    if (err != 0)
    {
        printf("[clipshot] prop condvar init error: %d\n", err);
        return 1;
    }

    err = pthread_mutex_init(&prop_mutex, NULL);
    if (err != 0)
    {
        printf("[clipshot] prop mutex init error: %d\n", err);
        return 1;
    }

    err = pthread_mutex_init(&shot_mutex, NULL);
    if (err != 0)
    {
        printf("[clipshot] shot mutex init error: %d\n", err);
        return 1;
    }

    xcb_connection_t *conn = xcb_connect(NULL, NULL);
    err = xcb_connection_has_error(conn);
    if (err > 0)
    {
        printf("[clipshot] x connection error: %d\n", err);
        return 1;
    }

    // printf("[clipshot] max request size: %"PRIu64" KB\n", (uint64_t)(xcb_get_maximum_request_length(conn)) * 4 / 1024);

    xcb_screen_t *screen = xcb_setup_roots_iterator(xcb_get_setup(conn)).data;

    holder = xcb_generate_id(conn);
    uint32_t mask = XCB_CW_EVENT_MASK;
    uint32_t values[] = {XCB_EVENT_MASK_PROPERTY_CHANGE};
    xcb_void_cookie_t w = xcb_create_window_checked(conn, XCB_COPY_FROM_PARENT, holder, screen->root,
                                                    0, 0, 1, 1, 1,
                                                    XCB_WINDOW_CLASS_INPUT_OUTPUT, screen->root_visual, mask, values);
    xcb_intern_atom_cookie_t c = xcb_intern_atom_unchecked(conn, 0, 9, "CLIPBOARD");
    xcb_intern_atom_cookie_t p = xcb_intern_atom_unchecked(conn, 0, 6, "ZALUPA");
    xcb_intern_atom_cookie_t t = xcb_intern_atom_unchecked(conn, 0, 7, "TARGETS");
    xcb_intern_atom_cookie_t png_cookie = xcb_intern_atom_unchecked(conn, 0, 9, "image/png");
    xcb_intern_atom_cookie_t atom_cookie = xcb_intern_atom_unchecked(conn, 0, 4, "ATOM");
    xcb_intern_atom_reply_t *reply = xcb_intern_atom_reply(conn, c, NULL);
    clipboard = reply->atom;
    reply = xcb_intern_atom_reply(conn, p, NULL);
    prop = reply->atom;
    reply = xcb_intern_atom_reply(conn, t, NULL);
    TARGETS = reply->atom;
    reply = xcb_intern_atom_reply(conn, png_cookie, NULL);
    png_target = reply->atom;
    reply = xcb_intern_atom_reply(conn, atom_cookie, NULL);
    ATOM = reply->atom;

    xcb_generic_error_t *werr = xcb_request_check(conn, w);
    if (werr != NULL)
    {
        printf("[clipshot] window creation failed, code: %d, major: %d, minor: %d\n", werr->error_code, werr->major_code, werr->minor_code);
        return 1;
    }

    pthread_t x_thr;
    err = pthread_create(&x_thr, NULL, handle_x_events, conn);
    if (err != 0)
    {
        printf("[clipshot] thread creation error: %s\n", strerror(err));
        return 1;
    }

    while (1)
    {
        mpv_event *event = mpv_wait_event(handle, -1);
        if (event->event_id == MPV_EVENT_SHUTDOWN)
            break;
        if (event->event_id == MPV_EVENT_CLIENT_MESSAGE)
        {
            mpv_event_client_message *msg = (mpv_event_client_message *)event->data;
            if (msg->num_args < 1)
            {
                printf("[clipshot] command name missing\n");
                continue;
            }
            const char *cmd = msg->args[0];
            if (strncmp(cmd, "clipshot", 8) != 0)
            {
                printf("[clipshot] unknown command %s\n", cmd);
                continue;
            }
            mpv_node result;
            int res = mpv_command_ret(handle, (const char *[]){"screenshot-raw", NULL}, &result);
            if (res < 0)
            {
                printf("[clipshot] error executing screenshot command: %d\n", res);
                continue;
            }

            if (result.format != MPV_FORMAT_NODE_MAP)
            {
                printf("[clipshot] expected map, got %d\n", result.format);
                mpv_free_node_contents(&result);
                continue;
            }

            mpv_node *width_node = get_map_value(result.u.list, "w");
            if (width_node == NULL)
            {
                printf("[clipshot] missing width key in map\n");
                mpv_free_node_contents(&result);
                continue;
            }
            int64_t width = width_node->u.int64;

            mpv_node *height_node = get_map_value(result.u.list, "h");
            if (height_node == NULL)
            {
                printf("[clipshot] missing height key in map\n");
                mpv_free_node_contents(&result);
                continue;
            }
            int64_t height = height_node->u.int64;

            mpv_node *stride_node = get_map_value(result.u.list, "stride");
            if (stride_node == NULL)
            {
                printf("[clipshot] missing stride key in map\n");
                mpv_free_node_contents(&result);
                continue;
            }
            int64_t stride = stride_node->u.int64;

            mpv_node *data_node = get_map_value(result.u.list, "data");
            if (data_node == NULL)
            {
                printf("[clipshot] missing data key in map\n");
                mpv_free_node_contents(&result);
                continue;
            }
            size_t data_size = data_node->u.ba->size;
            const uint8_t *data = data_node->u.ba->data;

            struct png_shot_buffer png_data;
            convert_to_png(width, height, stride, data, &png_data);

            pthread_mutex_lock(&shot_mutex);
            if (!shot_used)
            {
                free(shot_data.data);
            }
            shot_data = png_data;
            shot_used = 0;
            pthread_mutex_unlock(&shot_mutex);

            xcb_void_cookie_t p_c = xcb_change_property(conn, XCB_PROP_MODE_APPEND, holder, prop, prop, 8, 0, NULL);
            xcb_generic_error_t *perr = xcb_request_check(conn, p_c);
            if (perr != NULL)
            {
                printf("[clipshot] changing property failed, code: %d, major: %d, minor: %d\n", perr->error_code, perr->major_code, perr->minor_code);
            }

            pthread_mutex_lock(&prop_mutex);
            while (!fired)
                pthread_cond_wait(&prop_cond, &prop_mutex);
            xcb_timestamp_t t = prop_ts;
            fired = 0;
            pthread_mutex_unlock(&prop_mutex);

            xcb_void_cookie_t s = xcb_set_selection_owner_checked(conn, holder, clipboard, t);
            xcb_generic_error_t *serr = xcb_request_check(conn, s);
            if (serr != NULL)
            {
                printf("[clipshot] seting selection owner failed, code: %d, major: %d, minor: %d\n", serr->error_code, serr->major_code, serr->minor_code);
            }

            mpv_command(handle, (const char *[]){"show-text", "Screenshot copied to clipboard", NULL});
            mpv_free_node_contents(&result);
        }
    }
    return 0;
}
