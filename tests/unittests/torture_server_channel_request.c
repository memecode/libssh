#include "config.h"

#define LIBSSH_STATIC

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "torture.h"
#include "torture_key.h"

#include <libssh/libssh.h>

#define TEST_SERVER_HOST "127.0.0.1"
#define TEST_SERVER_PORT 2222

struct hostkey_state {
    const char *hostkey;
    char *hostkey_path;
    enum ssh_keytypes_e key_type;
    int fd;
};

struct server_result {
    bool queued_request_left;
};

static bool is_server_ready = false;
static pthread_mutex_t server_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t server_cond = PTHREAD_COND_INITIALIZER;

static int setup(void **state)
{
    struct hostkey_state *h = NULL;
    mode_t mask;
    int rc;

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    rc = ssh_init();
    if (rc != SSH_OK) {
        return -1;
    }

    h = (struct hostkey_state *)malloc(sizeof(struct hostkey_state));
    assert_non_null(h);

    h->hostkey_path = strdup("/tmp/libssh_hostkey_XXXXXX");
    assert_non_null(h->hostkey_path);

    mask = umask(S_IRWXO | S_IRWXG);
    h->fd = mkstemp(h->hostkey_path);
    umask(mask);
    assert_return_code(h->fd, errno);
    close(h->fd);

    h->key_type = SSH_KEYTYPE_ECDSA_P256;
    h->hostkey = torture_get_testkey(h->key_type, 0);

    torture_write_file(h->hostkey_path, h->hostkey);

    *state = h;

    /* Reset before every test */
    is_server_ready = false;

    return 0;
}

static int teardown(void **state)
{
    struct hostkey_state *h = (struct hostkey_state *)*state;

    unlink(h->hostkey_path);
    free(h->hostkey_path);
    free(h);

    ssh_finalize();

    return 0;
}

static void signal_flag(bool *flag)
{
    pthread_mutex_lock(&server_mutex);
    *flag = true;
    pthread_cond_signal(&server_cond);
    pthread_mutex_unlock(&server_mutex);
}

static void wait_flag(bool *flag)
{
    pthread_mutex_lock(&server_mutex);
    while (!*flag) {
        pthread_cond_wait(&server_cond, &server_mutex);
    }
    pthread_mutex_unlock(&server_mutex);
}

static ssh_channel accept_session_channel(ssh_session server)
{
    ssh_channel channel = NULL;
    ssh_message msg = NULL;

    while (channel == NULL) {
        msg = ssh_message_get(server);
        if (msg == NULL) {
            break;
        }

        if (ssh_message_type(msg) == SSH_REQUEST_AUTH &&
            ssh_message_subtype(msg) == SSH_AUTH_METHOD_PASSWORD) {
            ssh_message_auth_reply_success(msg, 0);
        } else if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL_OPEN &&
                   ssh_message_subtype(msg) == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(msg);
        } else {
            ssh_message_reply_default(msg);
        }
        ssh_message_free(msg);
    }

    return channel;
}

static void *server_thread(void *arg)
{
    struct hostkey_state *h = (struct hostkey_state *)arg;
    struct server_result *res = NULL;
    ssh_bind sshbind = NULL;
    ssh_session server = NULL;
    ssh_channel channel = NULL;
    ssh_event event = NULL;
    ssh_message msg = NULL;
    int rc;

    res = calloc(1, sizeof(struct server_result));
    assert_non_null(res);

    sshbind = torture_ssh_bind(TEST_SERVER_HOST,
                               TEST_SERVER_PORT,
                               h->key_type,
                               h->hostkey_path);
    assert_non_null(sshbind);

    server = ssh_new();
    assert_non_null(server);

    signal_flag(&is_server_ready);

    rc = ssh_bind_accept(sshbind, server);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_handle_key_exchange(server);
    assert_int_equal(rc, SSH_OK);

    ssh_set_auth_methods(server, SSH_AUTH_METHOD_PASSWORD);

    channel = accept_session_channel(server);
    assert_non_null(channel);

    event = ssh_event_new();
    assert_non_null(event);

    rc = ssh_event_add_session(event, server);
    assert_int_equal(rc, SSH_OK);

    /* The client sends a request and then closes the channel */
    while (!ssh_channel_is_closed(channel)) {
        rc = ssh_event_dopoll(event, 1000);
        assert_int_not_equal(rc, SSH_ERROR);
    }

    ssh_event_remove_session(event, server);
    ssh_event_free(event);

    ssh_channel_free(channel);

    /* Only look at the queue, do not wait for new packets */
    ssh_set_blocking(server, 0);

    /* Requests queued for the freed channel are dropped with it */
    msg = ssh_message_get(server);
    res->queued_request_left = (msg != NULL);
    ssh_message_free(msg);

    ssh_bind_free(sshbind);
    ssh_free(server);

    return res;
}

static void torture_server_channel_free_drops_queued_requests(void **state)
{
    struct hostkey_state *h = (struct hostkey_state *)*state;
    struct server_result *res = NULL;
    pthread_t server_pthread;
    ssh_session session = NULL;
    ssh_channel channel = NULL;
    unsigned int server_port = TEST_SERVER_PORT;
    int rc;

    rc = pthread_create(&server_pthread, NULL, server_thread, h);
    assert_return_code(rc, errno);

    wait_flag(&is_server_ready);

    session =
        torture_ssh_session(NULL, TEST_SERVER_HOST, &server_port, "foo", "bar");
    assert_non_null(session);

    channel = ssh_channel_new(session);
    assert_non_null(channel);

    rc = ssh_channel_open_session(channel);
    assert_int_equal(rc, SSH_OK);

    /* Send the request without waiting for its reply, then close */
    ssh_set_blocking(session, 0);
    rc = ssh_channel_request_env(channel, "LANG", "C");
    assert_int_equal(rc, SSH_AGAIN);
    ssh_set_blocking(session, 1);

    rc = ssh_channel_close(channel);
    assert_int_equal(rc, SSH_OK);

    rc = pthread_join(server_pthread, (void **)&res);
    assert_int_equal(rc, 0);
    assert_non_null(res);

    assert_false(res->queued_request_left);

    free(res);
    ssh_channel_free(channel);
    ssh_free(session);
}

int torture_run_tests(void)
{
    int rc;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            torture_server_channel_free_drops_queued_requests,
            setup,
            teardown),
    };

    rc = cmocka_run_group_tests(tests, NULL, NULL);
    return rc;
}
