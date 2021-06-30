/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* --- seL4 Imports Start --- */

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <inttypes.h>

/* --- seL4 Imports End --- */

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "fatal-signal.h"
#include "learning-switch.h"
#include "ofp-version-opt.h"
#include "openvswitch/ofpbuf.h"
#include "openflow/openflow.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "simap.h"
#include "stream-ssl.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "socket-util.h"


VLOG_DEFINE_THIS_MODULE(controller);

#define MAX_SWITCHES 16
#define MAX_LISTENERS 16

struct test_data {
    int num1;
    int num2;
};

struct switch_ {
    struct lswitch *lswitch;
};

/* -H, --hub: Learn the ports on which MAC addresses appear? */
static bool learn_macs = true;

/* -n, --noflow: Set up flows?  (If not, every packet is processed at the
 * controller.) */
static bool set_up_flows = true;

/* -N, --normal: Use "NORMAL" action instead of explicit port? */
static bool action_normal = false;

/* -w, --wildcard: 0 to disable wildcard flow entries, an OFPFW10_* bitmask to
 * enable specific wildcards, or UINT32_MAX to use the default wildcards. */
static uint32_t wildcards = 0;

/* --max-idle: Maximum idle time, in seconds, before flows expire. */
static int max_idle = 60;

/* --mute: If true, accept connections from switches but do not reply to any
 * of their messages (for debugging fail-open mode). */
static bool mute = false;

/* -q, --queue: default OpenFlow queue, none if UINT32_MAX. */
static uint32_t default_queue = UINT32_MAX;

/* -Q, --port-queue: map from port name to port number. */
static struct simap port_queues = SIMAP_INITIALIZER(&port_queues);

/* --with-flows: Flows to send to switch. */
static struct ofputil_flow_mod *default_flows;
static size_t n_default_flows;
static enum ofputil_protocol usable_protocols;

/* --unixctl: Name of unixctl socket, or null to use the default. */
static char *unixctl_path = NULL;

static void new_switch(struct switch_ *, struct vconn *);
static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

/* --- seL4 Helper Functions Start --- */

void block_event(int fd) {
    int val;
    /* Blocking read */
    int result = read(fd, &val, sizeof(val));
    if (result < 0) {
        printf("Error: %s\n", ovs_strerror(errno));
    } 

}

void emit_event(char* emit) {
    emit[0] = 1;
}

/* --- seL4 Helper Functions End --- */

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct switch_ switches[MAX_SWITCHES];
    struct pvconn *listeners[MAX_LISTENERS];
    int n_switches, n_listeners;
    int retval;
    int i;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemon_become_new_user(false);

    printf("Starting custom controller...\n");

    /* --- seL4 Test Component Interaction --- */
    
    printf("Starting custom seL4 integrated controller...\n");
    
    //char *uio_one_string = "This is a uio1 string\n\0";
    
    int dataport_length = 4096;
    
    char *dataport_name = "/dev/uio0";
    char *dataport1_name = "/dev/uio1";
    
    int fd = open(dataport_name, O_RDWR);
    ovs_assert(fd >= 0);
    int fd1 = open(dataport1_name, O_RDWR);
    ovs_assert(fd >= 0);
    
    void *dataport;
    if ((dataport = mmap(NULL, dataport_length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 1 * getpagesize())) == (void *) -1) {
        printf("mmap dataport0 failed\n");
        close(fd);
    }
    
    void *dataport1;
    if ((dataport1 = mmap(NULL, dataport_length, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 1 * getpagesize())) == (void *) -1) {
        printf("mmap dataport1 failed\n");
        close(fd);
    }
    
    char *emit;
    if ((emit = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 * getpagesize())) == (void *) -1) {
        printf("mmap emit failed\n");
        close(fd);
    }
    
    printf("CVC: Reading uio0\n");
    for (char *chr = dataport; *chr != 0; chr ++) {
        putchar(*chr);
    }
    fflush(stdout);
    
    struct test_data mydata;
    mydata.num1 = 14;
    mydata.num2 = 99;
    
    printf("CVC: Writing %lu bytes to uio1\n", sizeof(mydata));
    //size_t uio_one = uio_one_string ? strnlen(uio_one_string, 4095) + 1 : 0;
    //strncpy(dataport1, uio_one_string, uio_one);
    //memcpy(dataport1, &mydata, sizeof(mydata));
    printf("CVC: Reading uio0\n");
    for (char *chr = dataport; *chr != 0; chr ++) {
        putchar(*chr);
    }
    fflush(stdout);
    printf("CVC: Emitting uio0\n");
    emit_event(emit);
    printf("CVC: Waiting for done_init_emit_underlying in crossvm_init\n");
    block_event(fd);
    printf("Finished crossvm test script\n");
    munmap(dataport, dataport_length);
    munmap(dataport1, dataport_length);
    munmap(emit, dataport_length);
    close(fd);
    
    /* --- seL4 Test Component Interaction End --- */

    if (argc - optind < 1) {
        ovs_fatal(0, "at least one vconn argument required; "
                  "use --help for usage");
    }

    n_switches = n_listeners = 0;
    for (i = optind; i < argc; i++) {
        const char *name = argv[i];
        struct vconn *vconn;

        retval = vconn_open(name, get_allowed_ofp_versions(), DSCP_DEFAULT,
                            &vconn);
        if (!retval) {
            if (n_switches >= MAX_SWITCHES) {
                ovs_fatal(0, "max %d switch connections", n_switches);
            }
            new_switch(&switches[n_switches++], vconn);
            continue;
        } else if (retval == EAFNOSUPPORT) {
            struct pvconn *pvconn;
            retval = pvconn_open(name, get_allowed_ofp_versions(),
                                 DSCP_DEFAULT, &pvconn);
            if (!retval) {
                if (n_listeners >= MAX_LISTENERS) {
                    ovs_fatal(0, "max %d passive connections", n_listeners);
                }
                listeners[n_listeners++] = pvconn;
            }
        }
        if (retval) {
            VLOG_ERR("%s: connect: %s", name, ovs_strerror(retval));
        }
    }
    if (n_switches == 0 && n_listeners == 0) {
        ovs_fatal(0, "no active or passive switch connections");
    }

    daemonize_start(false);

    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    daemonize_complete();

    while (n_switches > 0 || n_listeners > 0) {
        /* Accept connections on listening vconns. */
        for (i = 0; i < n_listeners && n_switches < MAX_SWITCHES; ) {
            struct vconn *new_vconn;

            retval = pvconn_accept(listeners[i], &new_vconn);
            if (!retval || retval == EAGAIN) {
                if (!retval) {
                    new_switch(&switches[n_switches++], new_vconn);
                }
                i++;
            } else {
                pvconn_close(listeners[i]);
                listeners[i] = listeners[--n_listeners];
            }
        }

        /* Do some switching work.  . */
        for (i = 0; i < n_switches; ) {
            printf("Switches size: %ul\n", sizeof(&switches));
            struct switch_ *this = &switches[i];
            lswitch_run(this->lswitch);
            
            // Write lswitch to seL4 buffer
            memcpy(dataport1, &this->lswitch, sizeof(this->lswitch));
            emit_event(emit);
            block_event(fd);
            
            if (lswitch_is_alive(this->lswitch)) {
                i++;
            } else {
                lswitch_destroy(this->lswitch);
                switches[i] = switches[--n_switches];
            }
        }

        unixctl_server_run(unixctl);

        /* Wait for something to happen. */
        if (n_switches < MAX_SWITCHES) {
            for (i = 0; i < n_listeners; i++) {
                pvconn_wait(listeners[i]);
            }
        }
        for (i = 0; i < n_switches; i++) {
            struct switch_ *sw = &switches[i];
            lswitch_wait(sw->lswitch);
        }
        unixctl_server_wait(unixctl);
        poll_block();
    }

    return 0;
}

static void
new_switch(struct switch_ *sw, struct vconn *vconn)
{
    struct lswitch_config cfg;
    struct rconn *rconn;

    rconn = rconn_create(60, 0, DSCP_DEFAULT, get_allowed_ofp_versions());
    rconn_connect_unreliably(rconn, vconn, NULL);

    cfg.mode = (action_normal ? LSW_NORMAL
                : learn_macs ? LSW_LEARN
                : LSW_FLOOD);
    cfg.wildcards = wildcards;
    cfg.max_idle = set_up_flows ? max_idle : -1;
    cfg.default_flows = default_flows;
    cfg.n_default_flows = n_default_flows;
    cfg.usable_protocols = usable_protocols;
    cfg.default_queue = default_queue;
    cfg.port_queues = &port_queues;
    cfg.mute = mute;
    sw->lswitch = lswitch_create(rconn, &cfg);
}

static void
add_port_queue(char *s)
{
    char *save_ptr = NULL;
    char *port_name;
    char *queue_id;

    port_name = strtok_r(s, ":", &save_ptr);
    queue_id = strtok_r(NULL, "", &save_ptr);
    if (!queue_id) {
        ovs_fatal(0, "argument to -Q or --port-queue should take the form "
                  "\"<port-name>:<queue-id>\"");
    }

    if (!simap_put(&port_queues, port_name, atoi(queue_id))) {
        ovs_fatal(0, "<port-name> arguments for -Q or --port-queue must "
                  "be unique");
    }
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_MAX_IDLE = UCHAR_MAX + 1,
        OPT_PEER_CA_CERT,
        OPT_MUTE,
        OPT_WITH_FLOWS,
        OPT_UNIXCTL,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        OFP_VERSION_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"hub",         no_argument, NULL, 'H'},
        {"noflow",      no_argument, NULL, 'n'},
        {"normal",      no_argument, NULL, 'N'},
        {"wildcards",   optional_argument, NULL, 'w'},
        {"max-idle",    required_argument, NULL, OPT_MAX_IDLE},
        {"mute",        no_argument, NULL, OPT_MUTE},
        {"queue",       required_argument, NULL, 'q'},
        {"port-queue",  required_argument, NULL, 'Q'},
        {"with-flows",  required_argument, NULL, OPT_WITH_FLOWS},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        {"help",        no_argument, NULL, 'h'},
        DAEMON_LONG_OPTIONS,
        OFP_VERSION_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int indexptr;
        char *error;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, &indexptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'H':
            learn_macs = false;
            break;

        case 'n':
            set_up_flows = false;
            break;

        case OPT_MUTE:
            mute = true;
            break;

        case 'N':
            action_normal = true;
            break;

        case 'w':
            wildcards = optarg ? strtol(optarg, NULL, 16) : UINT32_MAX;
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                max_idle = OFP_FLOW_PERMANENT;
            } else {
                max_idle = atoi(optarg);
                if (max_idle < 1 || max_idle > 65535) {
                    ovs_fatal(0, "--max-idle argument must be between 1 and "
                              "65535 or the word 'permanent'");
                }
            }
            break;

        case 'q':
            default_queue = atoi(optarg);
            break;

        case 'Q':
            add_port_queue(optarg);
            break;

        case OPT_WITH_FLOWS:
            error = parse_ofp_flow_mod_file(optarg, NULL, NULL, OFPFC_ADD,
                                            &default_flows, &n_default_flows,
                                            &usable_protocols);
            if (error) {
                ovs_fatal(0, "%s", error);
            }
            break;

        case OPT_UNIXCTL:
            unixctl_path = optarg;
            break;

        case 'h':
            usage();

        VLOG_OPTION_HANDLERS
        OFP_VERSION_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    if (!simap_is_empty(&port_queues) || default_queue != UINT32_MAX) {
        if (action_normal) {
            ovs_error(0, "queue IDs are incompatible with -N or --normal; "
                      "not using OFPP_NORMAL");
            action_normal = false;
        }

        if (!learn_macs) {
            ovs_error(0, "queue IDs are incompatible with -H or --hub; "
                      "not acting as hub");
            learn_macs = true;
        }
    }
}

static void
usage(void)
{
    printf("%s: OpenFlow controller\n"
           "usage: %s [OPTIONS] METHOD\n"
           "where METHOD is any OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, true, false);
    daemon_usage();
    ofp_version_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -H, --hub               act as hub instead of learning switch\n"
           "  -n, --noflow            pass traffic, but don't add flows\n"
           "  --max-idle=SECS         max idle time for new flows\n"
           "  -N, --normal            use OFPP_NORMAL action\n"
           "  -w, --wildcards[=MASK]  wildcard (specified) bits in flows\n"
           "  -q, --queue=QUEUE-ID    OpenFlow queue ID to use for output\n"
           "  -Q PORT-NAME:QUEUE-ID   use QUEUE-ID for frames from PORT-NAME\n"
           "  --with-flows FILE       use the flows from FILE\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
