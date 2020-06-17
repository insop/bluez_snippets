#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>

#define CUSTOM_PROFILE_NAME		"Custom Profile Server"
#define CUSTOM_PROFILE_UUID		"fbd16a02-9e87-4c6d-8972-51eddd37f1a3"
#define CUSTOM_SERVICE_CLASS_UUID	"fbd16a03-9e87-4c6d-8972-51eddd37f1a3"
#define CUSTOM_PROFILE_PATH		"/org/bluez/custom_profile/server"

static const gchar introspection_xml[] =
	"<node>"
	"  <interface name='org.bluez.Profile1'>"
	"    <method name='Release' />"
	"    <method name='NewConnection'>"
	"      <arg type='o' name='device' direction='in' />"
	"      <arg type='h' name='fd' direction='in' />"
	"      <arg type='a{sv}' name='fd_properties' direction='in' />"
	"    </method>"
	"    <method name='RequestDisconnection'>"
	"      <arg type='o' name='device' direction='in' />"
	"    </method>"
	"  </interface>"
	"</node>";

static GMainLoop *loop;
static int fd;
static sem_t connected;

static void *read_thread_func(void *arg)
{
	int opts;
	int bytes_read;
	char message[20];

	/* Wait for connection and fd to become available */
	sem_wait(&connected);

	/* Allow blocking read */
	opts = fcntl(fd, F_GETFL);
	opts ^= O_NONBLOCK;
	fcntl(fd, F_SETFL, opts);

	bytes_read = read(fd, &message[0], sizeof(message) - 1);
	assert(bytes_read != -1);

	message[bytes_read] = 0;
	printf("Message received from client: \"%s\"\n", message);
	close(fd);
	g_main_loop_quit(loop);
	return NULL;
}

static void handle_method_call(GDBusConnection *conn, const char *sender, const char *path, const char *interface,
		const char *method, GVariant *params, GDBusMethodInvocation *invocation, void *userdata)
{
	int fd_handle;
	char *device_path;
	GError *error = NULL;
	GVariantIter *properties;
	GUnixFDList *fd_list;
	GDBusMessage *dbus_msg;

	if (strcmp(method, "NewConnection") == 0) {
		g_variant_get(params, "(&oha{sv})", &device_path, &fd_handle, &properties);
		printf("New connection from: %s\n", device_path);

		/* Retrieve file descriptor */
		dbus_msg = g_dbus_method_invocation_get_message(invocation);
		fd_list = g_dbus_message_get_unix_fd_list(dbus_msg);
		fd = g_unix_fd_list_get(fd_list, fd_handle, &error);
		g_assert_no_error(error);
		g_free(device_path);
		g_dbus_method_invocation_return_value(invocation, NULL);
		sem_post(&connected); /* Signal to read thread that fd is available */
	} else if (strcmp(method, "RequestDisconnection") == 0) {
		assert(0); /* Call not expected */
	} else if (strcmp(method, "Release") == 0) {
		assert(0); /* Call not expected */
	}
}

static GDBusInterfaceVTable vtable = {
	.method_call = handle_method_call,
};

int main(void)
{
	int err;
	pthread_t read_thread;
	GError *error = NULL;
	GDBusConnection *conn;
	GDBusMessage *dbus_msg;
	GVariantBuilder options;
	GDBusNodeInfo *introspection;
	GDBusInterfaceInfo *interface_info;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	g_assert_no_error(error);

	/* Register profile callbacks */
	introspection = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	g_assert_no_error(error);
	interface_info = g_dbus_node_info_lookup_interface(introspection, "org.bluez.Profile1");
	g_dbus_connection_register_object(conn, CUSTOM_PROFILE_PATH, interface_info, &vtable, NULL, NULL, &error);
	g_assert_no_error(error);
	g_dbus_node_info_unref(introspection);

	/* Register profile server */
	dbus_msg = g_dbus_message_new_method_call("org.bluez", "/org/bluez", "org.bluez.ProfileManager1", "RegisterProfile");

	g_variant_builder_init(&options, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&options, "{sv}", "Service", g_variant_new_string(CUSTOM_SERVICE_CLASS_UUID));
	g_variant_builder_add(&options, "{sv}", "Name", g_variant_new_string(CUSTOM_PROFILE_NAME));
	g_variant_builder_add(&options, "{sv}", "Role",	g_variant_new_string("server"));
	g_variant_builder_add(&options, "{sv}", "RequireAuthentication", g_variant_new_boolean(FALSE));
	g_variant_builder_add(&options, "{sv}", "RequireAuthorization", g_variant_new_boolean(FALSE));
	g_variant_builder_add(&options, "{sv}", "Channel", g_variant_new_uint16(0));	/* Auto select channel */

	g_dbus_message_set_body(dbus_msg, g_variant_new("(osa{sv})", CUSTOM_PROFILE_PATH, CUSTOM_PROFILE_UUID, &options));

	g_variant_builder_clear(&options);

	g_dbus_connection_send_message_with_reply_sync(conn, dbus_msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &error);
	g_assert_no_error(error);
	g_object_unref(dbus_msg);

	printf("Profile server registered with custom Service Class ID:\n\t%s\n", CUSTOM_SERVICE_CLASS_UUID);

	/* Create thread for reading from profile client */
	sem_init(&connected, 0, 0);
	err = pthread_create(&read_thread, NULL, &read_thread_func, NULL);
	assert(err == 0);

	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	pthread_join(read_thread, NULL);
	g_main_loop_unref(loop);
	g_object_unref(conn);
	printf("Profile server stopped\n");

	return 0;
}
