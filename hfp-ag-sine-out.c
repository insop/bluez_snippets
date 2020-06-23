#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sco.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>

#define HFP_PROFILE_NAME		"Hands-Free"
/* BlueZ uses HFP-AG Service Class ID 0x111f as Profile UUID */
#define HFP_PROFILE_UUID		"0000111f-0000-1000-8000-00805f9b34fb"
#define HFP_HF_SERVICE_CLASS_UUID	"0000111e-0000-1000-8000-00805f9b34fb"
#define HFP_PROFILE_PATH		"/org/bluez/hfp/client"

/* Device FC:A8:9A:A0:DD:C1 JBL Xtreme */
#define HFP_HF_BDADDR			"FC:A8:9A:A0:DD:C1"
#define HFP_HF_DEVICE_PATH		"/org/bluez/hci0/dev_FC_A8_9A_A0_DD_C1"

#define MAX_LEN_AT_CMD	512
#define MAX_LEN_AT_RSP	512

#define PCM_RATE	8000		/* 8000 PCM samples per second on HCI for 64 kb/s CVSD on the air */
#define PCM_SINE_FREQ	500		/* Frequency of output sine tone */
#define PCM_SINE_LEN	(1024)

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

static GDBusConnection *conn;
static GMainLoop *loop;
static int slc_fd;			/* Will hold fd received on NewConnection method call */
static bool quit;			/* Set to true by sco_thread_func to terminate slc_thread_func */

static sem_t connected;			/* Signalled on NewConnection method call */
static sem_t slc_established;		/* Signalled by slc_thread when Service Level Connection has been established */

static char at_command[MAX_LEN_AT_CMD + 1];
static char at_response[MAX_LEN_AT_RSP + 1];

static int16_t pcm_sine[PCM_SINE_LEN];	/* Sine table to hold PCM waveform */
static unsigned char sco_data_in[1024];	/* Dummy input buffer for reads from SCO socket */
static unsigned char *sco_data_out_ptr;	/* Pointer into sine table used for writing to SCO socket */

static void *slc_thread_func(void *arg)
{
	GError *error = NULL;
	GDBusMessage *dbus_msg;
	int bytes_read;
	struct pollfd fds[1];

	/* Connect to HFP HF */
	dbus_msg = g_dbus_message_new_method_call("org.bluez", HFP_HF_DEVICE_PATH, "org.bluez.Device1", "ConnectProfile");
	g_dbus_message_set_body(dbus_msg, g_variant_new("(s)", HFP_HF_SERVICE_CLASS_UUID));
	g_dbus_connection_send_message_with_reply_sync(conn, dbus_msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &error);
	g_assert_no_error(error);
	g_object_unref(dbus_msg);

	sem_wait(&connected);	/* Wait for connection and slc_fd to become available */

	fds[0].fd = slc_fd;
	fds[0].events = POLLIN;
	while (!quit) {
		bool established = false;

		fds[0].revents = 0;
		poll(fds, 1, 1000);
		if (!quit && (fds[0].revents & POLLIN)) {
			bytes_read = read(slc_fd, &at_command[0], MAX_LEN_AT_CMD);
			assert(bytes_read != -1);

			at_command[bytes_read] = 0;
			printf("AT command received from HF: %s\n", at_command);

			if (strncmp(at_command, "AT+BRSF=", strlen("AT+BRSF=")) == 0) {
				strcpy(at_response, "\r\n+BRSF: 0\r\n\r\nOK\r\n");
			} else if (strncmp(at_command, "AT+CIND=?", strlen("AT+CIND=?")) == 0) {
				strcpy(at_response, "\r\n+CIND: (\"service\",(0,1)),(\"call\",(0,1))\r\n\r\nOK\r\n");
			} else if (strncmp(at_command, "AT+CIND?", strlen("AT+CIND?")) == 0) {
				strcpy(at_response, "\r\n+CIND: 1,0\r\n\r\nOK\r\n");
			} else if (strncmp(at_command, "AT+CMER", strlen("AT+CMER")) == 0) {
				strcpy(at_response, "\r\nOK\r\n");
				established = true;
			} else {
				strcpy(at_response, "\r\nERROR\r\n");
			}

			printf("Response: %s", at_response);
			write(slc_fd, at_response, strlen(at_response));

			if (established)
				sem_post(&slc_established);
		}
	}
	close(slc_fd);
	return NULL;
}

static void *sco_thread_func(void *arg)
{
	int sock_fd;
	int ret;
	int i;
	struct sockaddr_sco sock_addr = {0};
	struct bt_voice voice_opts = {0};
	struct sco_options sco_opts = {0};
	socklen_t sco_opts_len = sizeof(sco_opts);
	int sco_data_len;
	time_t end_time;

	/* Wait for connection and fd to become available */
	sem_wait(&slc_established);
	printf("Service Level Connection established\n");

	/* Open SCO connection */
	sock_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	assert(sock_fd >= 0);

	voice_opts.setting = BT_VOICE_CVSD_16BIT;
	ret = setsockopt(sock_fd, SOL_BLUETOOTH, BT_VOICE, &voice_opts, sizeof(voice_opts));
	assert(ret != -1);

	sock_addr.sco_family = AF_BLUETOOTH;
	str2ba(HFP_HF_BDADDR, &sock_addr.sco_bdaddr);

	ret = connect(sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
	assert(ret != -1);

	ret = getsockopt(sock_fd, SOL_SCO, SCO_OPTIONS, &sco_opts, &sco_opts_len);
	assert(ret != -1);

	/* Reported mtu apparently includes 1 byte HCI Packet Type plus 3 bytes HCI SCO Data packet header */
	sco_data_len = sco_opts.mtu - 4;

	/* Send sine wave out */
	for (i = 0; i < PCM_SINE_LEN; i++)
		pcm_sine[i] = 32767. * sin((double)i * 2.0 * M_PI * (double)PCM_SINE_FREQ / (double)PCM_RATE);

	assert(sco_data_len <= sizeof(sco_data_in));
	i = 0;
	end_time = time(NULL) + 10;	/* Send the sine tone for 10 seconds */
	while (time(NULL) < end_time) {
		int bytes_read;
		/* Use read to pace write (is there a better way?) */
		bytes_read = read(sock_fd, &sco_data_in[0], sco_data_len);
		if (bytes_read != -1) {
			sco_data_out_ptr = (unsigned char *)&pcm_sine[i];
			i += bytes_read / 2;
			i = i % (PCM_RATE / PCM_SINE_FREQ);
			write(sock_fd, sco_data_out_ptr, bytes_read);
		}
	}

	close(sock_fd);
	quit = true;
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
		slc_fd = g_unix_fd_list_get(fd_list, fd_handle, &error);
		g_assert_no_error(error);
		g_free(device_path);
		g_dbus_method_invocation_return_value(invocation, NULL);
		sem_post(&connected); /* Signal to write thread that fd is available */
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
	pthread_t slc_thread;
	pthread_t sco_thread;
	GError *error = NULL;
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
	g_dbus_connection_register_object(conn, HFP_PROFILE_PATH, interface_info, &vtable, NULL, NULL, &error);
	g_assert_no_error(error);
	g_dbus_node_info_unref(introspection);

	/* Register profile client */
	dbus_msg = g_dbus_message_new_method_call("org.bluez", "/org/bluez", "org.bluez.ProfileManager1", "RegisterProfile");

	g_variant_builder_init(&options, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&options, "{sv}", "Name", g_variant_new_string(HFP_PROFILE_NAME));
	g_variant_builder_add(&options, "{sv}", "Role",	g_variant_new_string("client"));
	g_variant_builder_add(&options, "{sv}", "RequireAuthentication", g_variant_new_boolean(FALSE));
	g_variant_builder_add(&options, "{sv}", "RequireAuthorization", g_variant_new_boolean(FALSE));

	g_dbus_message_set_body(dbus_msg, g_variant_new("(osa{sv})", HFP_PROFILE_PATH, HFP_PROFILE_UUID, &options));

	g_variant_builder_clear(&options);

	g_dbus_connection_send_message_with_reply_sync(conn, dbus_msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &error);
	g_assert_no_error(error);
	g_object_unref(dbus_msg);

	printf("Profile client registered with Profile ID:\n\t%s\n", HFP_PROFILE_UUID);

	/* Create thread for Initializing and handling Service Level Connection */
	sem_init(&connected, 0, 0);
	err = pthread_create(&slc_thread, NULL, &slc_thread_func, NULL);
	assert(err == 0);

	/* Create thread for opening SCO connection and sending sine wave audio out */
	sem_init(&slc_established, 0, 0);
	err = pthread_create(&sco_thread, NULL, &sco_thread_func, NULL);
	assert(err == 0);

	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	pthread_join(slc_thread, NULL);
	pthread_join(sco_thread, NULL);
	g_main_loop_unref(loop);
	g_object_unref(conn);
	printf("Profile client stopped\n");

	return 0;
}
