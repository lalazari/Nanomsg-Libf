/*
    Copyright (c) 2012-2013 Martin Sustrik  All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom
    the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
*/

#include "clibfabric.h"
#include "slibfabric.h"

#include "../../libfabric.h"

#include "../utils/dns.h"
#include "../utils/port.h"
#include "../utils/iface.h"
#include "../utils/backoff.h"
#include "../utils/literal.h"

#include "../../aio/fsm.h"
#include "../../aio/usock.h"

#include "../../utils/err.h"
#include "../../utils/cont.h"
#include "../../utils/alloc.h"
#include "../../utils/fast.h"
#include "../../utils/int.h"
#include "../../utils/attr.h"

#include <string.h>

#if defined NN_HAVE_WINDOWS
#include "../../utils/win.h"
#else
#include <unistd.h>
//#include <netinet/in.h>
//#include <netinet/libfabric.h>
#endif

#define NN_CLIBFABRIC_STATE_IDLE 1
#define NN_CLIBFABRIC_STATE_RESOLVING 2
#define NN_CLIBFABRIC_STATE_STOPPING_DNS 3
#define NN_CLIBFABRIC_STATE_CONNECTING 4
#define NN_CLIBFABRIC_STATE_ACTIVE 5
#define NN_CLIBFABRIC_STATE_STOPPING_SLIBFABRIC 6
#define NN_CLIBFABRIC_STATE_STOPPING_USOCK 7
#define NN_CLIBFABRIC_STATE_WAITING 8
#define NN_CLIBFABRIC_STATE_STOPPING_BACKOFF 9
#define NN_CLIBFABRIC_STATE_STOPPING_SLIBFABRIC_FINAL 10
#define NN_CLIBFABRIC_STATE_STOPPING 11

#define NN_CLIBFABRIC_SRC_USOCK 1
#define NN_CLIBFABRIC_SRC_RECONNECT_TIMER 2
#define NN_CLIBFABRIC_SRC_DNS 3
#define NN_CLIBFABRIC_SRC_SLIBFABRIC 4

struct nn_clibfabric {

    /*  The state machine. */
    struct nn_fsm fsm;
    int state;

    /*  This object is a specific type of endpoint.
        Thus it is derived from epbase. */
    struct nn_epbase epbase;

    /*  The underlying LIBFABRIC socket. */
    struct nn_usock usock;

    /*  Used to wait before retrying to connect. */
    struct nn_backoff retry;

    /*  State machine that handles the active part of the connection
        lifetime. */
    struct nn_slibfabric slibfabric;

    /*  DNS resolver used to convert textual address into actual IP address
        along with the variable to hold the result. */
    struct nn_dns dns;
    struct nn_dns_result dns_result;
};

/*  nn_epbase virtual interface implementation. */
static void nn_clibfabric_stop (struct nn_epbase *self);
static void nn_clibfabric_destroy (struct nn_epbase *self);
const struct nn_epbase_vfptr nn_clibfabric_epbase_vfptr = {
    nn_clibfabric_stop,
    nn_clibfabric_destroy
};

/*  Private functions. */
static void nn_clibfabric_handler (struct nn_fsm *self, int src, int type,
    void *srcptr);
static void nn_clibfabric_shutdown (struct nn_fsm *self, int src, int type,
    void *srcptr);
static void nn_clibfabric_start_resolving (struct nn_clibfabric *self);
static void nn_clibfabric_start_connecting (struct nn_clibfabric *self,
    struct sockaddr_storage *ss, size_t sslen);

int nn_clibfabric_create (void *hint, struct nn_epbase **epbase)
{
    int rc;
    const char *addr;
    size_t addrlen;
    const char *semicolon;
    const char *hostname;
    const char *colon;
    const char *end;
    struct sockaddr_storage ss;
    size_t sslen;
    int ipv4only;
    size_t ipv4onlylen;
    struct nn_clibfabric *self;
    int reconnect_ivl;
    int reconnect_ivl_max;
    size_t sz;

    /*  Allocate the new endpoint object. */
    self = nn_alloc (sizeof (struct nn_clibfabric), "clibfabric");
    alloc_assert (self);

    /*  Initalise the endpoint. */
    nn_epbase_init (&self->epbase, &nn_clibfabric_epbase_vfptr, hint);

    /*  Check whether IPv6 is to be used. */
    ipv4onlylen = sizeof (ipv4only);
    nn_epbase_getopt (&self->epbase, NN_SOL_SOCKET, NN_IPV4ONLY,
        &ipv4only, &ipv4onlylen);
    nn_assert (ipv4onlylen == sizeof (ipv4only));

    /*  Start parsing the address. */
    addr = nn_epbase_getaddr (&self->epbase);
    addrlen = strlen (addr);
    semicolon = strchr (addr, ';');
    hostname = semicolon ? semicolon + 1 : addr;
    colon = strrchr (addr, ':');
    end = addr + addrlen;

    /*  Parse the port. */
    if (nn_slow (!colon)) {
        nn_epbase_term (&self->epbase);
        return -EINVAL;
    }
    rc = nn_port_resolve (colon + 1, end - colon - 1);
    if (nn_slow (rc < 0)) {
        nn_epbase_term (&self->epbase);
        return -EINVAL;
    }

    /*  Check whether the host portion of the address is either a literal
        or a valid hostname. */
    if (nn_dns_check_hostname (hostname, colon - hostname) < 0 &&
          nn_literal_resolve (hostname, colon - hostname, ipv4only,
          &ss, &sslen) < 0) {
        nn_epbase_term (&self->epbase);
        return -EINVAL;
    }

    /*  If local address is specified, check whether it is valid. */
    if (semicolon) {
        rc = nn_iface_resolve (addr, semicolon - addr, ipv4only, &ss, &sslen);
        if (rc < 0) {
            nn_epbase_term (&self->epbase);
            return -ENODEV;
        }
    }

    /*  Initialise the structure. */
    nn_fsm_init_root (&self->fsm, nn_clibfabric_handler, nn_clibfabric_shutdown,
        nn_epbase_getctx (&self->epbase));
    self->state = NN_CLIBFABRIC_STATE_IDLE;
    nn_usock_init (&self->usock, NN_CLIBFABRIC_SRC_USOCK, &self->fsm);
    sz = sizeof (reconnect_ivl);
    nn_epbase_getopt (&self->epbase, NN_SOL_SOCKET, NN_RECONNECT_IVL,
        &reconnect_ivl, &sz);
    nn_assert (sz == sizeof (reconnect_ivl));
    sz = sizeof (reconnect_ivl_max);
    nn_epbase_getopt (&self->epbase, NN_SOL_SOCKET, NN_RECONNECT_IVL_MAX,
        &reconnect_ivl_max, &sz);
    nn_assert (sz == sizeof (reconnect_ivl_max));
    if (reconnect_ivl_max == 0)
        reconnect_ivl_max = reconnect_ivl;
    nn_backoff_init (&self->retry, NN_CLIBFABRIC_SRC_RECONNECT_TIMER,
        reconnect_ivl, reconnect_ivl_max, &self->fsm);
    nn_slibfabric_init (&self->slibfabric, NN_CLIBFABRIC_SRC_SLIBFABRIC, &self->epbase, &self->fsm);
    nn_dns_init (&self->dns, NN_CLIBFABRIC_SRC_DNS, &self->fsm);

    /*  Start the state machine. */
    nn_fsm_start (&self->fsm);

    /*  Return the base class as an out parameter. */
    *epbase = &self->epbase;

    return 0;
}

static void nn_clibfabric_stop (struct nn_epbase *self)
{
    struct nn_clibfabric *clibfabric;

    clibfabric = nn_cont (self, struct nn_clibfabric, epbase);

    nn_fsm_stop (&clibfabric->fsm);
}

static void nn_clibfabric_destroy (struct nn_epbase *self)
{
    struct nn_clibfabric *clibfabric;

    clibfabric = nn_cont (self, struct nn_clibfabric, epbase);

    nn_dns_term (&clibfabric->dns);
    nn_slibfabric_term (&clibfabric->slibfabric);
    nn_backoff_term (&clibfabric->retry);
    nn_usock_term (&clibfabric->usock);
    nn_fsm_term (&clibfabric->fsm);
    nn_epbase_term (&clibfabric->epbase);

    nn_free (clibfabric);
}

static void nn_clibfabric_shutdown (struct nn_fsm *self, int src, int type,
    NN_UNUSED void *srcptr)
{
    struct nn_clibfabric *clibfabric;

    clibfabric = nn_cont (self, struct nn_clibfabric, fsm);

    if (nn_slow (src == NN_FSM_ACTION && type == NN_FSM_STOP)) {
        if (!nn_slibfabric_isidle (&clibfabric->slibfabric)) {
            nn_epbase_stat_increment (&clibfabric->epbase,
                NN_STAT_DROPPED_CONNECTIONS, 1);
            nn_slibfabric_stop (&clibfabric->slibfabric);
        }
        clibfabric->state = NN_CLIBFABRIC_STATE_STOPPING_SLIBFABRIC_FINAL;
    }
    if (nn_slow (clibfabric->state == NN_CLIBFABRIC_STATE_STOPPING_SLIBFABRIC_FINAL)) {
        if (!nn_slibfabric_isidle (&clibfabric->slibfabric))
            return;
        nn_backoff_stop (&clibfabric->retry);
        nn_usock_stop (&clibfabric->usock);
        nn_dns_stop (&clibfabric->dns);
        clibfabric->state = NN_CLIBFABRIC_STATE_STOPPING;
    }
    if (nn_slow (clibfabric->state == NN_CLIBFABRIC_STATE_STOPPING)) {
        if (!nn_backoff_isidle (&clibfabric->retry) ||
              !nn_usock_isidle (&clibfabric->usock) ||
              !nn_dns_isidle (&clibfabric->dns))
            return;
        clibfabric->state = NN_CLIBFABRIC_STATE_IDLE;
        nn_fsm_stopped_noevent (&clibfabric->fsm);
        nn_epbase_stopped (&clibfabric->epbase);
        return;
    }

    nn_fsm_bad_state (clibfabric->state, src, type);
}

static void nn_clibfabric_handler (struct nn_fsm *self, int src, int type,
    NN_UNUSED void *srcptr)
{
    struct nn_clibfabric *clibfabric;

    clibfabric = nn_cont (self, struct nn_clibfabric, fsm);

    switch (clibfabric->state) {

/******************************************************************************/
/*  IDLE state.                                                               */
/*  The state machine wasn't yet started.                                     */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_IDLE:
        switch (src) {

        case NN_FSM_ACTION:
            switch (type) {
            case NN_FSM_START:
                nn_clibfabric_start_resolving (clibfabric);
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  RESOLVING state.                                                          */
/*  Name of the host to connect to is being resolved to get an IP address.    */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_RESOLVING:
        switch (src) {

        case NN_CLIBFABRIC_SRC_DNS:
            switch (type) {
            case NN_DNS_DONE:
                nn_dns_stop (&clibfabric->dns);
                clibfabric->state = NN_CLIBFABRIC_STATE_STOPPING_DNS;
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  STOPPING_DNS state.                                                       */
/*  dns object was asked to stop but it haven't stopped yet.                  */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_STOPPING_DNS:
        switch (src) {

        case NN_CLIBFABRIC_SRC_DNS:
            switch (type) {
            case NN_DNS_STOPPED:
                if (clibfabric->dns_result.error == 0) {
                    nn_clibfabric_start_connecting (clibfabric, &clibfabric->dns_result.addr,
                        clibfabric->dns_result.addrlen);
                    return;
                }
                nn_backoff_start (&clibfabric->retry);
                clibfabric->state = NN_CLIBFABRIC_STATE_WAITING;
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  CONNECTING state.                                                         */
/*  Non-blocking connect is under way.                                        */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_CONNECTING:
        switch (src) {

        case NN_CLIBFABRIC_SRC_USOCK:
            switch (type) {
            case NN_USOCK_CONNECTED:
                nn_slibfabric_start (&clibfabric->slibfabric, &clibfabric->usock);
                clibfabric->state = NN_CLIBFABRIC_STATE_ACTIVE;
                nn_epbase_stat_increment (&clibfabric->epbase,
                    NN_STAT_INPROGRESS_CONNECTIONS, -1);
                nn_epbase_stat_increment (&clibfabric->epbase,
                    NN_STAT_ESTABLISHED_CONNECTIONS, 1);
                nn_epbase_clear_error (&clibfabric->epbase);
                return;
            case NN_USOCK_ERROR:
                nn_epbase_set_error (&clibfabric->epbase,
                    nn_usock_geterrno (&clibfabric->usock));
                nn_usock_stop (&clibfabric->usock);
                clibfabric->state = NN_CLIBFABRIC_STATE_STOPPING_USOCK;
                nn_epbase_stat_increment (&clibfabric->epbase,
                    NN_STAT_INPROGRESS_CONNECTIONS, -1);
                nn_epbase_stat_increment (&clibfabric->epbase,
                    NN_STAT_CONNECT_ERRORS, 1);
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  ACTIVE state.                                                             */
/*  Connection is established and handled by the slibfabric state machine.          */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_ACTIVE:
        switch (src) {

        case NN_CLIBFABRIC_SRC_SLIBFABRIC:
            switch (type) {
            case NN_SLIBFABRIC_ERROR:
                nn_slibfabric_stop (&clibfabric->slibfabric);
                clibfabric->state = NN_CLIBFABRIC_STATE_STOPPING_SLIBFABRIC;
                nn_epbase_stat_increment (&clibfabric->epbase,
                    NN_STAT_BROKEN_CONNECTIONS, 1);
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  STOPPING_SLIBFABRIC state.                                                      */
/*  slibfabric object was asked to stop but it haven't stopped yet.                 */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_STOPPING_SLIBFABRIC:
        switch (src) {

        case NN_CLIBFABRIC_SRC_SLIBFABRIC:
            switch (type) {
            case NN_USOCK_SHUTDOWN:
                return;
            case NN_SLIBFABRIC_STOPPED:
                nn_usock_stop (&clibfabric->usock);
                clibfabric->state = NN_CLIBFABRIC_STATE_STOPPING_USOCK;
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  STOPPING_USOCK state.                                                     */
/*  usock object was asked to stop but it haven't stopped yet.                */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_STOPPING_USOCK:
        switch (src) {

        case NN_CLIBFABRIC_SRC_USOCK:
            switch (type) {
            case NN_USOCK_SHUTDOWN:
                return;
            case NN_USOCK_STOPPED:
                nn_backoff_start (&clibfabric->retry);
                clibfabric->state = NN_CLIBFABRIC_STATE_WAITING;
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  WAITING state.                                                            */
/*  Waiting before re-connection is attempted. This way we won't overload     */
/*  the system by continuous re-connection attemps.                           */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_WAITING:
        switch (src) {

        case NN_CLIBFABRIC_SRC_RECONNECT_TIMER:
            switch (type) {
            case NN_BACKOFF_TIMEOUT:
                nn_backoff_stop (&clibfabric->retry);
                clibfabric->state = NN_CLIBFABRIC_STATE_STOPPING_BACKOFF;
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  STOPPING_BACKOFF state.                                                   */
/*  backoff object was asked to stop, but it haven't stopped yet.             */
/******************************************************************************/
    case NN_CLIBFABRIC_STATE_STOPPING_BACKOFF:
        switch (src) {

        case NN_CLIBFABRIC_SRC_RECONNECT_TIMER:
            switch (type) {
            case NN_BACKOFF_STOPPED:
                nn_clibfabric_start_resolving (clibfabric);
                return;
            default:
                nn_fsm_bad_action (clibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (clibfabric->state, src, type);
        }

/******************************************************************************/
/*  Invalid state.                                                            */
/******************************************************************************/
    default:
        nn_fsm_bad_state (clibfabric->state, src, type);
    }
}

/******************************************************************************/
/*  State machine actions.                                                    */
/******************************************************************************/

static void nn_clibfabric_start_resolving (struct nn_clibfabric *self)
{
    const char *addr;
    const char *begin;
    const char *end;
    int ipv4only;
    size_t ipv4onlylen;

    /*  Extract the hostname part from address string. */
    addr = nn_epbase_getaddr (&self->epbase);
    begin = strchr (addr, ';');
    if (!begin)
        begin = addr;
    else
        ++begin;
    end = strrchr (addr, ':');
    nn_assert (end);

    /*  Check whether IPv6 is to be used. */
    ipv4onlylen = sizeof (ipv4only);
    nn_epbase_getopt (&self->epbase, NN_SOL_SOCKET, NN_IPV4ONLY,
        &ipv4only, &ipv4onlylen);
    nn_assert (ipv4onlylen == sizeof (ipv4only));

    /*  TODO: Get the actual value of IPV4ONLY option. */
    nn_dns_start (&self->dns, begin, end - begin, ipv4only, &self->dns_result);

    self->state = NN_CLIBFABRIC_STATE_RESOLVING;
}

static void nn_clibfabric_start_connecting (struct nn_clibfabric *self,
    struct sockaddr_storage *ss, size_t sslen)
{
    int rc;
    struct sockaddr_storage remote;
    size_t remotelen;
    struct sockaddr_storage local;
    size_t locallen;
    const char *addr;
    const char *end;
    const char *colon;
    const char *semicolon;
    uint16_t port;
    int ipv4only;
    size_t ipv4onlylen;
    int val;
    size_t sz;

    /*  Create IP address from the address string. */
    addr = nn_epbase_getaddr (&self->epbase);
    memset (&remote, 0, sizeof (remote));

    /*  Parse the port. */
    end = addr + strlen (addr);
    colon = strrchr (addr, ':');
    rc = nn_port_resolve (colon + 1, end - colon - 1);
    errnum_assert (rc > 0, -rc);
    port = rc;

    /*  Check whether IPv6 is to be used. */
    ipv4onlylen = sizeof (ipv4only);
    nn_epbase_getopt (&self->epbase, NN_SOL_SOCKET, NN_IPV4ONLY,
        &ipv4only, &ipv4onlylen);
    nn_assert (ipv4onlylen == sizeof (ipv4only));

    /*  Parse the local address, if any. */
    semicolon = strchr (addr, ';');
    memset (&local, 0, sizeof (local));
    if (semicolon)
        rc = nn_iface_resolve (addr, semicolon - addr, ipv4only,
            &local, &locallen);
    else
        rc = nn_iface_resolve ("*", 1, ipv4only, &local, &locallen);
    if (nn_slow (rc < 0)) {
        nn_backoff_start (&self->retry);
        self->state = NN_CLIBFABRIC_STATE_WAITING;
        return;
    }

    /*  Combine the remote address and the port. */
    remote = *ss;
    remotelen = sslen;
    if (remote.ss_family == AF_INET)
        ((struct sockaddr_in*) &remote)->sin_port = htons (port);
    else if (remote.ss_family == AF_INET6)
        ((struct sockaddr_in6*) &remote)->sin6_port = htons (port);
    else
        nn_assert (0);

    /*  Try to start the underlying socket. */
    rc = nn_usock_start (&self->usock, remote.ss_family, SOCK_STREAM, 0);
    if (nn_slow (rc < 0)) {
        nn_backoff_start (&self->retry);
        self->state = NN_CLIBFABRIC_STATE_WAITING;
        return;
    }

    /*  Set the relevant socket options. */
    sz = sizeof (val);
    nn_epbase_getopt (&self->epbase, NN_SOL_SOCKET, NN_SNDBUF, &val, &sz);
    nn_assert (sz == sizeof (val));
    nn_usock_setsockopt (&self->usock, SOL_SOCKET, SO_SNDBUF,
        &val, sizeof (val));
    sz = sizeof (val);
    nn_epbase_getopt (&self->epbase, NN_SOL_SOCKET, NN_RCVBUF, &val, &sz);
    nn_assert (sz == sizeof (val));
    nn_usock_setsockopt (&self->usock, SOL_SOCKET, SO_RCVBUF,
        &val, sizeof (val));

    /*  Bind the socket to the local network interface. */
    rc = nn_usock_bind (&self->usock, (struct sockaddr*) &local, locallen);
    if (nn_slow (rc != 0)) {
        nn_backoff_start (&self->retry);
        self->state = NN_CLIBFABRIC_STATE_WAITING;
        return;
    }

    /*  Start connecting. */
    nn_usock_connect (&self->usock, (struct sockaddr*) &remote, remotelen);
    self->state = NN_CLIBFABRIC_STATE_CONNECTING;
    nn_epbase_stat_increment (&self->epbase,
        NN_STAT_INPROGRESS_CONNECTIONS, 1);
}

