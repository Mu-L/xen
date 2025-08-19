/* 
    Simple prototype Xen Store Daemon providing simple tree-like database.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; If not, see <http://www.gnu.org/licenses/>.
*/
#include <sys/types.h>
#include <sys/mman.h>
#include <syslog.h>
#include "talloc.h"
#include "core.h"
#include "utils.h"
#include <xen/grant_table.h>
#include <mini-os/lib.h>
#include <mini-os/9pfront.h>
#include <mini-os/sched.h>
#include <mini-os/xenbus.h>
#include <mini-os/xmalloc.h>

#define P9_STATE_PATH	"device/9pfs/0/state"

static void *p9_device;

void finish_daemonize(void)
{
}

struct connection *add_socket_connection(int fd)
{
	barf("socket based connection without sockets");
}

/*
 * minios stubdom looks up dom0's event channel from the command line
 * (--event).  The stubdom's own event channel is returned directly.
 *
 * Any other existing domains from dom0less/Hyperlaunch will have
 * the event channel in the xenstore page, so lookup here isn't necessary.
 * --event would not be set, so it would default to 0.
 */
evtchn_port_t get_domain_evtchn(unsigned int domid)
{
	if (domid == stub_domid)
		return xenbus_evtchn;
	else if (domid == priv_domid)
		return dom0_event;

	return 0;
}

void *xenbus_map(void)
{
	return xengnttab_map_grant_ref(*xgt_handle, xenbus_master_domid(),
			GNTTAB_RESERVED_XENSTORE, PROT_READ|PROT_WRITE);
}

void unmap_xenbus(void *interface)
{
	xengnttab_unmap(*xgt_handle, interface, 1);
}

void early_init(bool live_update, bool dofork, const char *pidfile)
{
	stub_domid = get_domid();
	if (stub_domid == DOMID_INVALID)
		barf("could not get own domid");
}

void late_init(bool live_update)
{
}

void set_special_fds(void)
{
}

void handle_special_fds(void)
{
}

int get_socket_fd(void)
{
	return -1;
}

void set_socket_fd(int fd)
{
}

xenevtchn_handle *evtchn_fdopen(int fd)
{
	return xenevtchn_open(NULL, XENEVTCHN_NO_CLOEXEC);
}

int evtchn_rebind(int port)
{
	return xenevtchn_bind(xce_handle, port);
}

static void mount_thread(void *p)
{
	xenbus_event_queue events = NULL;
	char *err;
	char *dummy;

	err = xenbus_watch_path_token(XBT_NIL, P9_STATE_PATH, "9pfs", &events);
	if (err) {
		log("error \"%s\" when setting watch on \"%s\"\n", err,
		    P9_STATE_PATH);
		free(err);
		return;
	}

	for (;;) {
		xenbus_wait_for_watch(&events);

		/*
		 * We only care for existence of the state node.
		 * State changes are handled in init_9pfront().
		 */
		err = xenbus_read(XBT_NIL, P9_STATE_PATH, &dummy);
		if (!err)
			break;
		free(err);
	}

	free(dummy);

	err = xenbus_unwatch_path_token(XBT_NIL, P9_STATE_PATH, "9pfs");
	if (err) {
		log("error \"%s\" when unwatching \"%s\", leaking watch\n",
		    err, P9_STATE_PATH);
		free(err);
	}

	p9_device = init_9pfront2(0, XENSTORE_LIB_DIR, INIT9P_FLAG_KEXEC);

	/* Start logging if selected. */
	reopen_log();
}

void mount_9pfs(bool live_update)
{
	if (!live_update)
		create_thread("mount-9pfs", mount_thread, NULL);
	else {
		p9_device = init_9pfront2(0, XENSTORE_LIB_DIR,
					  INIT9P_FLAG_REINIT);
		reopen_log();
	}
}

const char *xenstore_rundir(void)
{
	return XENSTORE_LIB_DIR;
}
