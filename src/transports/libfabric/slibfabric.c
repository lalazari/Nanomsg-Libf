/*
    Copyright (c) 2013 Martin Sustrik  All rights reserved.

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

#include "slibfabric.h"

#include "../../utils/err.h"
#include "../../utils/cont.h"
#include "../../utils/fast.h"
#include "../../utils/wire.h"
#include "../../utils/int.h"
#include "../../utils/attr.h"

/*  States of the object as a whole. */
#define NN_SLIBFABRIC_STATE_IDLE 1
#define NN_SLIBFABRIC_STATE_PROTOHDR 2
#define NN_SLIBFABRIC_STATE_STOPPING_STREAMHDR 3
#define NN_SLIBFABRIC_STATE_ACTIVE 4
#define NN_SLIBFABRIC_STATE_SHUTTING_DOWN 5
#define NN_SLIBFABRIC_STATE_DONE 6
#define NN_SLIBFABRIC_STATE_STOPPING 7

/*  Possible states of the inbound part of the object. */
#define NN_SLIBFABRIC_INSTATE_HDR 1
#define NN_SLIBFABRIC_INSTATE_BODY 2
#define NN_SLIBFABRIC_INSTATE_HASMSG 3

/*  Possible states of the outbound part of the object. */
#define NN_SLIBFABRIC_OUTSTATE_IDLE 1
#define NN_SLIBFABRIC_OUTSTATE_SENDING 2

/*  Subordinate srcptr objects. */
#define NN_SLIBFABRIC_SRC_USOCK 1
#define NN_SLIBFABRIC_SRC_STREAMHDR 2

/*  Stream is a special type of pipe. Implementation of the virtual pipe API. */
static int nn_slibfabric_send (struct nn_pipebase *self, struct nn_msg *msg);
static int nn_slibfabric_recv (struct nn_pipebase *self, struct nn_msg *msg);
const struct nn_pipebase_vfptr nn_slibfabric_pipebase_vfptr = {
    nn_slibfabric_send,
    nn_slibfabric_recv
};

/*  Private functions. */
static void nn_slibfabric_handler (struct nn_fsm *self, int src, int type,
    void *srcptr);
static void nn_slibfabric_shutdown (struct nn_fsm *self, int src, int type,
    void *srcptr);

void nn_slibfabric_init (struct nn_slibfabric *self, int src,
    struct nn_epbase *epbase, struct nn_fsm *owner)
{
    nn_fsm_init (&self->fsm, nn_slibfabric_handler, nn_slibfabric_shutdown,
        src, self, owner);
    self->state = NN_SLIBFABRIC_STATE_IDLE;
    nn_streamhdr_init (&self->streamhdr, NN_SLIBFABRIC_SRC_STREAMHDR, &self->fsm);
    self->usock = NULL;
    self->usock_owner.src = -1;
    self->usock_owner.fsm = NULL;
    nn_pipebase_init (&self->pipebase, &nn_slibfabric_pipebase_vfptr, epbase);
    self->instate = -1;
    nn_msg_init (&self->inmsg, 0);
    self->outstate = -1;
    nn_msg_init (&self->outmsg, 0);
    nn_fsm_event_init (&self->done);
}

void nn_slibfabric_term (struct nn_slibfabric *self)
{
    nn_assert_state (self, NN_SLIBFABRIC_STATE_IDLE);

    nn_fsm_event_term (&self->done);
    nn_msg_term (&self->outmsg);
    nn_msg_term (&self->inmsg);
    nn_pipebase_term (&self->pipebase);
    nn_streamhdr_term (&self->streamhdr);
    nn_fsm_term (&self->fsm);
}

int nn_slibfabric_isidle (struct nn_slibfabric *self)
{
    return nn_fsm_isidle (&self->fsm);
}

void nn_slibfabric_start (struct nn_slibfabric *self, struct nn_usock *usock)
{
    /*  Take ownership of the underlying socket. */
    nn_assert (self->usock == NULL && self->usock_owner.fsm == NULL);
    self->usock_owner.src = NN_SLIBFABRIC_SRC_USOCK;
    self->usock_owner.fsm = &self->fsm;
    nn_usock_swap_owner (usock, &self->usock_owner);
    self->usock = usock;

    /*  Launch the state machine. */
    nn_fsm_start (&self->fsm);
}

void nn_slibfabric_stop (struct nn_slibfabric *self)
{
    nn_fsm_stop (&self->fsm);
}

static int nn_slibfabric_send (struct nn_pipebase *self, struct nn_msg *msg)
{
    struct nn_slibfabric *slibfabric;
    struct nn_iovec iov [3];

    slibfabric = nn_cont (self, struct nn_slibfabric, pipebase);

    nn_assert_state (slibfabric, NN_SLIBFABRIC_STATE_ACTIVE);
    nn_assert (slibfabric->outstate == NN_SLIBFABRIC_OUTSTATE_IDLE);

    /*  Move the message to the local storage. */
    nn_msg_term (&slibfabric->outmsg);
    nn_msg_mv (&slibfabric->outmsg, msg);

    /*  Serialise the message header. */
    nn_putll (slibfabric->outhdr, nn_chunkref_size (&slibfabric->outmsg.sphdr) +
        nn_chunkref_size (&slibfabric->outmsg.body));

    /*  Start async sending. */
    iov [0].iov_base = slibfabric->outhdr;
    iov [0].iov_len = sizeof (slibfabric->outhdr);
    iov [1].iov_base = nn_chunkref_data (&slibfabric->outmsg.sphdr);
    iov [1].iov_len = nn_chunkref_size (&slibfabric->outmsg.sphdr);
    iov [2].iov_base = nn_chunkref_data (&slibfabric->outmsg.body);
    iov [2].iov_len = nn_chunkref_size (&slibfabric->outmsg.body);
    nn_usock_send (slibfabric->usock, iov, 3);

    slibfabric->outstate = NN_SLIBFABRIC_OUTSTATE_SENDING;

    return 0;
}

static int nn_slibfabric_recv (struct nn_pipebase *self, struct nn_msg *msg)
{
    struct nn_slibfabric *slibfabric;

    slibfabric = nn_cont (self, struct nn_slibfabric, pipebase);

    nn_assert_state (slibfabric, NN_SLIBFABRIC_STATE_ACTIVE);
    nn_assert (slibfabric->instate == NN_SLIBFABRIC_INSTATE_HASMSG);

    /*  Move received message to the user. */
    nn_msg_mv (msg, &slibfabric->inmsg);
    nn_msg_init (&slibfabric->inmsg, 0);

    /*  Start receiving new message. */
    slibfabric->instate = NN_SLIBFABRIC_INSTATE_HDR;
    nn_usock_recv (slibfabric->usock, slibfabric->inhdr, sizeof (slibfabric->inhdr), NULL);

    return 0;
}

static void nn_slibfabric_shutdown (struct nn_fsm *self, int src, int type,
    NN_UNUSED void *srcptr)
{
    struct nn_slibfabric *slibfabric;

    slibfabric = nn_cont (self, struct nn_slibfabric, fsm);

    if (nn_slow (src == NN_FSM_ACTION && type == NN_FSM_STOP)) {
        nn_pipebase_stop (&slibfabric->pipebase);
        nn_streamhdr_stop (&slibfabric->streamhdr);
        slibfabric->state = NN_SLIBFABRIC_STATE_STOPPING;
    }
    if (nn_slow (slibfabric->state == NN_SLIBFABRIC_STATE_STOPPING)) {
        if (nn_streamhdr_isidle (&slibfabric->streamhdr)) {
            nn_usock_swap_owner (slibfabric->usock, &slibfabric->usock_owner);
            slibfabric->usock = NULL;
            slibfabric->usock_owner.src = -1;
            slibfabric->usock_owner.fsm = NULL;
            slibfabric->state = NN_SLIBFABRIC_STATE_IDLE;
            nn_fsm_stopped (&slibfabric->fsm, NN_SLIBFABRIC_STOPPED);
            return;
        }
        return;
    }

    nn_fsm_bad_state(slibfabric->state, src, type);
}

static void nn_slibfabric_handler (struct nn_fsm *self, int src, int type,
    NN_UNUSED void *srcptr)
{
    int rc;
    struct nn_slibfabric *slibfabric;
    uint64_t size;
    int opt;
    size_t opt_sz = sizeof (opt);

    slibfabric = nn_cont (self, struct nn_slibfabric, fsm);

    switch (slibfabric->state) {

/******************************************************************************/
/*  IDLE state.                                                               */
/******************************************************************************/
    case NN_SLIBFABRIC_STATE_IDLE:
        switch (src) {

        case NN_FSM_ACTION:
            switch (type) {
            case NN_FSM_START:
                nn_streamhdr_start (&slibfabric->streamhdr, slibfabric->usock,
                    &slibfabric->pipebase);
                slibfabric->state = NN_SLIBFABRIC_STATE_PROTOHDR;
                return;
            default:
                nn_fsm_bad_action (slibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (slibfabric->state, src, type);
        }

/******************************************************************************/
/*  PROTOHDR state.                                                           */
/******************************************************************************/
    case NN_SLIBFABRIC_STATE_PROTOHDR:
        switch (src) {

        case NN_SLIBFABRIC_SRC_STREAMHDR:
            switch (type) {
            case NN_STREAMHDR_OK:

                /*  Before moving to the active state stop the streamhdr
                    state machine. */
                nn_streamhdr_stop (&slibfabric->streamhdr);
                slibfabric->state = NN_SLIBFABRIC_STATE_STOPPING_STREAMHDR;
                return;

            case NN_STREAMHDR_ERROR:

                /* Raise the error and move directly to the DONE state.
                   streamhdr object will be stopped later on. */
                slibfabric->state = NN_SLIBFABRIC_STATE_DONE;
                nn_fsm_raise (&slibfabric->fsm, &slibfabric->done, NN_SLIBFABRIC_ERROR);
                return;

            default:
                nn_fsm_bad_action (slibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (slibfabric->state, src, type);
        }

/******************************************************************************/
/*  STOPPING_STREAMHDR state.                                                 */
/******************************************************************************/
    case NN_SLIBFABRIC_STATE_STOPPING_STREAMHDR:
        switch (src) {

        case NN_SLIBFABRIC_SRC_STREAMHDR:
            switch (type) {
            case NN_STREAMHDR_STOPPED:

                 /*  Start the pipe. */
                 rc = nn_pipebase_start (&slibfabric->pipebase);
                 if (nn_slow (rc < 0)) {
                    slibfabric->state = NN_SLIBFABRIC_STATE_DONE;
                    nn_fsm_raise (&slibfabric->fsm, &slibfabric->done, NN_SLIBFABRIC_ERROR);
                    return;
                 }

                 /*  Start receiving a message in asynchronous manner. */
                 slibfabric->instate = NN_SLIBFABRIC_INSTATE_HDR;
                 nn_usock_recv (slibfabric->usock, &slibfabric->inhdr,
                     sizeof (slibfabric->inhdr), NULL);

                 /*  Mark the pipe as available for sending. */
                 slibfabric->outstate = NN_SLIBFABRIC_OUTSTATE_IDLE;

                 slibfabric->state = NN_SLIBFABRIC_STATE_ACTIVE;
                 return;

            default:
                nn_fsm_bad_action (slibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (slibfabric->state, src, type);
        }

/******************************************************************************/
/*  ACTIVE state.                                                             */
/******************************************************************************/
    case NN_SLIBFABRIC_STATE_ACTIVE:
        switch (src) {

        case NN_SLIBFABRIC_SRC_USOCK:
            switch (type) {
            case NN_USOCK_SENT:

                /*  The message is now fully sent. */
                nn_assert (slibfabric->outstate == NN_SLIBFABRIC_OUTSTATE_SENDING);
                slibfabric->outstate = NN_SLIBFABRIC_OUTSTATE_IDLE;
                nn_msg_term (&slibfabric->outmsg);
                nn_msg_init (&slibfabric->outmsg, 0);
                nn_pipebase_sent (&slibfabric->pipebase);
                return;

            case NN_USOCK_RECEIVED:

                switch (slibfabric->instate) {
                case NN_SLIBFABRIC_INSTATE_HDR:

                    /*  Message header was received. Check that message size
                        is acceptable by comparing with NN_RCVMAXSIZE;
                        if it's too large, drop the connection. */
                    size = nn_getll (slibfabric->inhdr);

                    nn_pipebase_getopt (&slibfabric->pipebase, NN_SOL_SOCKET,
                        NN_RCVMAXSIZE, &opt, &opt_sz);

                    if (opt != -1 && size > opt) {
                        slibfabric->state = NN_SLIBFABRIC_STATE_DONE;
                        nn_fsm_raise (&slibfabric->fsm, &slibfabric->done, NN_SLIBFABRIC_ERROR);
                        return;
                    }

                    /*  Allocate memory for the message. */
                    nn_msg_term (&slibfabric->inmsg);
                    nn_msg_init (&slibfabric->inmsg, (size_t) size);

                    /*  Special case when size of the message body is 0. */
                    if (!size) {
                        slibfabric->instate = NN_SLIBFABRIC_INSTATE_HASMSG;
                        nn_pipebase_received (&slibfabric->pipebase);
                        return;
                    }

                    /*  Start receiving the message body. */
                    slibfabric->instate = NN_SLIBFABRIC_INSTATE_BODY;
                    nn_usock_recv (slibfabric->usock,
                        nn_chunkref_data (&slibfabric->inmsg.body),
                       (size_t) size, NULL);

                    return;

                case NN_SLIBFABRIC_INSTATE_BODY:

                    /*  Message body was received. Notify the owner that it
                        can receive it. */
                    slibfabric->instate = NN_SLIBFABRIC_INSTATE_HASMSG;
                    nn_pipebase_received (&slibfabric->pipebase);

                    return;

                default:
                    nn_fsm_error("Unexpected socket instate",
                        slibfabric->state, src, type);
                }

            case NN_USOCK_SHUTDOWN:
                nn_pipebase_stop (&slibfabric->pipebase);
                slibfabric->state = NN_SLIBFABRIC_STATE_SHUTTING_DOWN;
                return;

            case NN_USOCK_ERROR:
                nn_pipebase_stop (&slibfabric->pipebase);
                slibfabric->state = NN_SLIBFABRIC_STATE_DONE;
                nn_fsm_raise (&slibfabric->fsm, &slibfabric->done, NN_SLIBFABRIC_ERROR);
                return;

            default:
                nn_fsm_bad_action (slibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (slibfabric->state, src, type);
        }

/******************************************************************************/
/*  SHUTTING_DOWN state.                                                      */
/*  The underlying connection is closed. We are just waiting that underlying  */
/*  usock being closed                                                        */
/******************************************************************************/
    case NN_SLIBFABRIC_STATE_SHUTTING_DOWN:
        switch (src) {

        case NN_SLIBFABRIC_SRC_USOCK:
            switch (type) {
            case NN_USOCK_ERROR:
                slibfabric->state = NN_SLIBFABRIC_STATE_DONE;
                nn_fsm_raise (&slibfabric->fsm, &slibfabric->done, NN_SLIBFABRIC_ERROR);
                return;
            default:
                nn_fsm_bad_action (slibfabric->state, src, type);
            }

        default:
            nn_fsm_bad_source (slibfabric->state, src, type);
        }


/******************************************************************************/
/*  DONE state.                                                               */
/*  The underlying connection is closed. There's nothing that can be done in  */
/*  this state except stopping the object.                                    */
/******************************************************************************/
    case NN_SLIBFABRIC_STATE_DONE:
        nn_fsm_bad_source (slibfabric->state, src, type);

/******************************************************************************/
/*  Invalid state.                                                            */
/******************************************************************************/
    default:
        nn_fsm_bad_state (slibfabric->state, src, type);
    }
}

