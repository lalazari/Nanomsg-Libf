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

#include "alibfabric.h"

#include "../../utils/err.h"
#include "../../utils/cont.h"
#include "../../utils/attr.h"

#define NN_ALIBFABRIC_STATE_IDLE 1
#define NN_ALIBFABRIC_STATE_ACCEPTING 2
#define NN_ALIBFABRIC_STATE_ACTIVE 3
#define NN_ALIBFABRIC_STATE_STOPPING_SLIBFABRIC 4
#define NN_ALIBFABRIC_STATE_STOPPING_USOCK 5
#define NN_ALIBFABRIC_STATE_DONE 6
#define NN_ALIBFABRIC_STATE_STOPPING_SLIBFABRIC_FINAL 7
#define NN_ALIBFABRIC_STATE_STOPPING 8

#define NN_ALIBFABRIC_SRC_USOCK 1
#define NN_ALIBFABRIC_SRC_SLIBFABRIC 2
#define NN_ALIBFABRIC_SRC_LISTENER 3

/*  Private functions. */
static void nn_alibfabric_handler (struct nn_fsm *self, int src, int type,
    void *srcptr);
static void nn_alibfabric_shutdown (struct nn_fsm *self, int src, int type,
    void *srcptr);

void nn_alibfabric_init (struct nn_alibfabric *self, int src,
    struct nn_epbase *epbase, struct nn_fsm *owner)
{
    nn_fsm_init (&self->fsm, nn_alibfabric_handler, nn_alibfabric_shutdown,
        src, self, owner);
    self->state = NN_ALIBFABRIC_STATE_IDLE;
    self->epbase = epbase;
    nn_usock_init (&self->usock, NN_ALIBFABRIC_SRC_USOCK, &self->fsm);
    self->listener = NULL;
    self->listener_owner.src = -1;
    self->listener_owner.fsm = NULL;
    nn_slibfabric_init (&self->slibfabric, NN_ALIBFABRIC_SRC_SLIBFABRIC, epbase, &self->fsm);
    nn_fsm_event_init (&self->accepted);
    nn_fsm_event_init (&self->done);
    nn_list_item_init (&self->item);
}

void nn_alibfabric_term (struct nn_alibfabric *self)
{
    nn_assert_state (self, NN_ALIBFABRIC_STATE_IDLE);

    nn_list_item_term (&self->item);
    nn_fsm_event_term (&self->done);
    nn_fsm_event_term (&self->accepted);
    nn_slibfabric_term (&self->slibfabric);
    nn_usock_term (&self->usock);
    nn_fsm_term (&self->fsm);
}

int nn_alibfabric_isidle (struct nn_alibfabric *self)
{
    return nn_fsm_isidle (&self->fsm);
}

void nn_alibfabric_start (struct nn_alibfabric *self, struct nn_usock *listener)
{
    nn_assert_state (self, NN_ALIBFABRIC_STATE_IDLE);

    /*  Take ownership of the listener socket. */
    self->listener = listener;
    self->listener_owner.src = NN_ALIBFABRIC_SRC_LISTENER;
    self->listener_owner.fsm = &self->fsm;
    nn_usock_swap_owner (listener, &self->listener_owner);

    /*  Start the state machine. */
    nn_fsm_start (&self->fsm);
}

void nn_alibfabric_stop (struct nn_alibfabric *self)
{
    nn_fsm_stop (&self->fsm);
}

static void nn_alibfabric_shutdown (struct nn_fsm *self, int src, int type,
    NN_UNUSED void *srcptr)
{
    struct nn_alibfabric *alibfabric;

    alibfabric = nn_cont (self, struct nn_alibfabric, fsm);

    if (nn_slow (src == NN_FSM_ACTION && type == NN_FSM_STOP)) {
        if (!nn_slibfabric_isidle (&alibfabric->slibfabric)) {
            nn_epbase_stat_increment (alibfabric->epbase,
                NN_STAT_DROPPED_CONNECTIONS, 1);
            nn_slibfabric_stop (&alibfabric->slibfabric);
        }
        alibfabric->state = NN_ALIBFABRIC_STATE_STOPPING_SLIBFABRIC_FINAL;
    }
    if (nn_slow (alibfabric->state == NN_ALIBFABRIC_STATE_STOPPING_SLIBFABRIC_FINAL)) {
        if (!nn_slibfabric_isidle (&alibfabric->slibfabric))
            return;
        nn_usock_stop (&alibfabric->usock);
        alibfabric->state = NN_ALIBFABRIC_STATE_STOPPING;
    }
    if (nn_slow (alibfabric->state == NN_ALIBFABRIC_STATE_STOPPING)) {
        if (!nn_usock_isidle (&alibfabric->usock))
            return;
       if (alibfabric->listener) {
            nn_assert (alibfabric->listener_owner.fsm);
            nn_usock_swap_owner (alibfabric->listener, &alibfabric->listener_owner);
            alibfabric->listener = NULL;
            alibfabric->listener_owner.src = -1;
            alibfabric->listener_owner.fsm = NULL;
        }
        alibfabric->state = NN_ALIBFABRIC_STATE_IDLE;
        nn_fsm_stopped (&alibfabric->fsm, NN_ALIBFABRIC_STOPPED);
        return;
    }

    nn_fsm_bad_action(alibfabric->state, src, type);
}

static void nn_alibfabric_handler (struct nn_fsm *self, int src, int type,
    NN_UNUSED void *srcptr)
{
    struct nn_alibfabric *alibfabric;
    int val;
    size_t sz;

    alibfabric = nn_cont (self, struct nn_alibfabric, fsm);

    switch (alibfabric->state) {

/******************************************************************************/
/*  IDLE state.                                                               */
/*  The state machine wasn't yet started.                                     */
/******************************************************************************/
    case NN_ALIBFABRIC_STATE_IDLE:
        switch (src) {

        case NN_FSM_ACTION:
            switch (type) {
            case NN_FSM_START:
                nn_usock_accept (&alibfabric->usock, alibfabric->listener);
                alibfabric->state = NN_ALIBFABRIC_STATE_ACCEPTING;
                return;
            default:
                nn_fsm_bad_action (alibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (alibfabric->state, src, type);
        }

/******************************************************************************/
/*  ACCEPTING state.                                                          */
/*  Waiting for incoming connection.                                          */
/******************************************************************************/
    case NN_ALIBFABRIC_STATE_ACCEPTING:
        switch (src) {

        case NN_ALIBFABRIC_SRC_USOCK:
            switch (type) {
            case NN_USOCK_ACCEPTED:
                nn_epbase_clear_error (alibfabric->epbase);

                /*  Set the relevant socket options. */
                sz = sizeof (val);
                nn_epbase_getopt (alibfabric->epbase, NN_SOL_SOCKET, NN_SNDBUF,
                    &val, &sz);
                nn_assert (sz == sizeof (val));
                nn_usock_setsockopt (&alibfabric->usock, SOL_SOCKET, SO_SNDBUF,
                    &val, sizeof (val));
                sz = sizeof (val);
                nn_epbase_getopt (alibfabric->epbase, NN_SOL_SOCKET, NN_RCVBUF,
                    &val, &sz);
                nn_assert (sz == sizeof (val));
                nn_usock_setsockopt (&alibfabric->usock, SOL_SOCKET, SO_RCVBUF,
                    &val, sizeof (val));

                /*  Return ownership of the listening socket to the parent. */
                nn_usock_swap_owner (alibfabric->listener, &alibfabric->listener_owner);
                alibfabric->listener = NULL;
                alibfabric->listener_owner.src = -1;
                alibfabric->listener_owner.fsm = NULL;
                nn_fsm_raise (&alibfabric->fsm, &alibfabric->accepted, NN_ALIBFABRIC_ACCEPTED);

                /*  Start the slibfabric state machine. */
                nn_usock_activate (&alibfabric->usock);
                nn_slibfabric_start (&alibfabric->slibfabric, &alibfabric->usock);
                alibfabric->state = NN_ALIBFABRIC_STATE_ACTIVE;

                nn_epbase_stat_increment (alibfabric->epbase,
                    NN_STAT_ACCEPTED_CONNECTIONS, 1);

                return;

            default:
                nn_fsm_bad_action (alibfabric->state, src, type);
            }

        case NN_ALIBFABRIC_SRC_LISTENER:
            switch (type) {

            case NN_USOCK_ACCEPT_ERROR:
                nn_epbase_set_error (alibfabric->epbase,
                    nn_usock_geterrno(alibfabric->listener));
                nn_epbase_stat_increment (alibfabric->epbase,
                    NN_STAT_ACCEPT_ERRORS, 1);
                nn_usock_accept (&alibfabric->usock, alibfabric->listener);
                return;

            default:
                nn_fsm_bad_action (alibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (alibfabric->state, src, type);
        }

/******************************************************************************/
/*  ACTIVE state.                                                             */
/******************************************************************************/
    case NN_ALIBFABRIC_STATE_ACTIVE:
        switch (src) {

        case NN_ALIBFABRIC_SRC_SLIBFABRIC:
            switch (type) {
            case NN_SLIBFABRIC_ERROR:
                nn_slibfabric_stop (&alibfabric->slibfabric);
                alibfabric->state = NN_ALIBFABRIC_STATE_STOPPING_SLIBFABRIC;
                nn_epbase_stat_increment (alibfabric->epbase,
                    NN_STAT_BROKEN_CONNECTIONS, 1);
                return;
            default:
                nn_fsm_bad_action (alibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (alibfabric->state, src, type);
        }

/******************************************************************************/
/*  STOPPING_SLIBFABRIC state.                                                      */
/******************************************************************************/
    case NN_ALIBFABRIC_STATE_STOPPING_SLIBFABRIC:
        switch (src) {

        case NN_ALIBFABRIC_SRC_SLIBFABRIC:
            switch (type) {
            case NN_USOCK_SHUTDOWN:
                return;
            case NN_SLIBFABRIC_STOPPED:
                nn_usock_stop (&alibfabric->usock);
                alibfabric->state = NN_ALIBFABRIC_STATE_STOPPING_USOCK;
                return;
            default:
                nn_fsm_bad_action (alibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (alibfabric->state, src, type);
        }

/******************************************************************************/
/*  STOPPING_USOCK state.                                                      */
/******************************************************************************/
    case NN_ALIBFABRIC_STATE_STOPPING_USOCK:
        switch (src) {

        case NN_ALIBFABRIC_SRC_USOCK:
            switch (type) {
            case NN_USOCK_SHUTDOWN:
                return;
            case NN_USOCK_STOPPED:
                nn_fsm_raise (&alibfabric->fsm, &alibfabric->done, NN_ALIBFABRIC_ERROR);
                alibfabric->state = NN_ALIBFABRIC_STATE_DONE;
                return;
            default:
                nn_fsm_bad_action (alibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (alibfabric->state, src, type);
        }

/******************************************************************************/
/*  Invalid state.                                                            */
/******************************************************************************/
    default:
        nn_fsm_bad_state (alibfabric->state, src, type);
    }
}

