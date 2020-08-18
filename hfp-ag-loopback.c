/*
 * test code to connect 2 devices (earbuds) with HFP
 */
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

#define MAYBE_UNUSED __attribute__((unused))


#define HFP_PROFILE_NAME		"Hands-Free"
/* BlueZ uses HFP-AG Service Class ID 0x111f as Profile UUID */
#define HFP_PROFILE_UUID		"0000111f-0000-1000-8000-00805f9b34fb"
#define HFP_HF_SERVICE_CLASS_UUID	"0000111e-0000-1000-8000-00805f9b34fb"
#define HFP_PROFILE_PATH		"/org/bluez/hfp/client"

#define JABRA_E_75t 1
#define SONY_WH_1000 1

// NOTE proper BDADDR is required
#if JABRA_E_75t
#define HFP_HF_BDADDR			"70:BF:"
#define HFP_HF_DEVICE_PATH		"/org/bluez/hci0/dev_70_BF"
#endif

// WH-100
#if SONY_WH_1000
#define HFP_HF_BDADDR2			"70:26:"
#define HFP_HF_DEVICE_PATH2		"/org/bluez/hci0/dev_70_26"
#endif

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

#define NUM_DEV 2
static GDBusConnection *conn;
static GMainLoop *loop;
static int slc_fd[NUM_DEV];			/* Will hold fd received on NewConnection method call */
static int sock_fd[NUM_DEV]; /* sco socket */

static bool quit;			/* Set to true by sco_thread_func to terminate slc_thread_func */

static sem_t connected[NUM_DEV];			/* Signalled on NewConnection method call */
static sem_t slc_established[NUM_DEV];		/* Signalled by slc_thread when Service Level Connection has been established */

static char at_command[MAX_LEN_AT_CMD + 1];
static char at_response[MAX_LEN_AT_RSP + 1];

static int16_t pcm_sine[PCM_SINE_LEN];	/* Sine table to hold PCM waveform */
static unsigned char sco_data_in[NUM_DEV][1024];	/* Dummy input buffer for reads from SCO socket */

struct thread_args {
  int i;
  const char *path;
  const char *bd_addr;
};

static struct thread_args th_args[2] = {
        { 0, HFP_HF_DEVICE_PATH, HFP_HF_BDADDR },
        { 1, HFP_HF_DEVICE_PATH2, HFP_HF_BDADDR2 },
};


static void *slc_thread_func(void *arg)
{
	GError *error = NULL;
	GDBusMessage *dbus_msg;
	int bytes_read;
	struct pollfd fds[1];

	struct thread_args *th = (struct thread_args *) arg;
  int index = th->i;
  const char *path = th->path;
  const char *bd_addr = th->bd_addr;

	/* Connect to HFP HF */
	dbus_msg = g_dbus_message_new_method_call("org.bluez", path, "org.bluez.Device1", "ConnectProfile");
	g_dbus_message_set_body(dbus_msg, g_variant_new("(s)", HFP_HF_SERVICE_CLASS_UUID));
	g_dbus_connection_send_message_with_reply_sync(conn, dbus_msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &error);
	g_assert_no_error(error);
	g_object_unref(dbus_msg);

	printf("%s:%d i=%d %s\n", __func__, __LINE__, index, path);
	sem_wait(&connected[index]);	/* Wait for connection and slc_fd to become available */

	fds[0].fd = slc_fd[index];
	fds[0].events = POLLIN;
	while (!quit) {
		bool established = false;

		fds[0].revents = 0;
		poll(fds, 1, 1000);
		//printf("%s:%d \n", __func__, __LINE__);
		if (!quit && (fds[0].revents & POLLIN)) {
			bytes_read = read(slc_fd[index], &at_command[0], MAX_LEN_AT_CMD);
      printf("[%d]\n", index);
			assert(bytes_read != -1);

			at_command[bytes_read] = 0;
			printf("[%d] AT command received from HF: %s\n", index, at_command);

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
				//strcpy(at_response, "\r\nERROR\r\n");
        strcpy(at_response, "\r\nUNHANDLED\r\n");
			}

			printf("[%d, %s] Response: %s", index, bd_addr, at_response);
			write(slc_fd[index], at_response, strlen(at_response));

			if (established)
				sem_post(&slc_established[index]);
		}
	}
	close(slc_fd[index]);
	return NULL;
}

int get_other_dev_index(int index) {
  return index == 0 ? 1: 0;
}

static void *sco_thread_func(void *arg)
{
	int ret;
	int i;
	struct sockaddr_sco sock_addr = {0};
	struct bt_voice voice_opts = {0};
	struct sco_options sco_opts = {0};
	socklen_t sco_opts_len = sizeof(sco_opts);
	int sco_data_len;

  struct thread_args *th = (struct thread_args *) arg;
  int index = th->i;
  const char *bd_addr = th->bd_addr;

  sleep(5);

  /* Wait for connection and fd to become available */
	sem_wait(&slc_established[index]);
	printf("Service Level Connection established i=%d, bd_addr %s\n", index, bd_addr);

	/* Open SCO connection */
	sock_fd[index] = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
  printf("[%d]\n", index);
  assert(sock_fd[index] >= 0);

	voice_opts.setting = BT_VOICE_CVSD_16BIT;
	ret = setsockopt(sock_fd[index], SOL_BLUETOOTH, BT_VOICE, &voice_opts, sizeof(voice_opts));
	assert(ret != -1);

	sock_addr.sco_family = AF_BLUETOOTH;
	str2ba(bd_addr, &sock_addr.sco_bdaddr);

	ret = connect(sock_fd[index], (struct sockaddr *)&sock_addr, sizeof(sock_addr));
	assert(ret != -1);

	ret = getsockopt(sock_fd[index], SOL_SCO, SCO_OPTIONS, &sco_opts, &sco_opts_len);
	assert(ret != -1);

	/* Reported mtu apparently includes 1 byte HCI Packet Type plus 3 bytes HCI SCO Data packet header */
	sco_data_len = sco_opts.mtu - 4;

	/* Send sine wave out */
	for (i = 0; i < PCM_SINE_LEN; i++)
		pcm_sine[i] = 32767. * sin((double)i * 2.0 * M_PI * (double)PCM_SINE_FREQ / (double)PCM_RATE);

	assert(sco_data_len <= sizeof(sco_data_in[index]));
	i = 0;

	while (true) {
		int MAYBE_UNUSED bytes_read;
		/* Use read to pace write (is there a better way?) */
		int read_index = index;
		bytes_read = read(sock_fd[read_index], &sco_data_in[read_index][0], sco_data_len);
//		printf("%s:%d read %d fd %d\n", __func__, __LINE__, bytes_read, read_index);
    // XXX
    if (index == 1)
      continue;
		if (bytes_read != -1) {
      printf("Read %d bytes (%02x %02x ...) from earbuds%d microphone\n", bytes_read, sco_data_in[read_index][0], sco_data_in[read_index][1], read_index);
		  // write to other device
		  int write_index = get_other_dev_index(index);
      // use buffer from read index
			int MAYBE_UNUSED n = write(sock_fd[write_index], &sco_data_in[read_index][0], bytes_read);
//			printf("%s:%d written %d to fd %d\n", __func__, __LINE__, n, write_index);
//			assert(n == bytes_read);
      if (n == bytes_read)
        printf("Write %d bytes (%02x %02x ...)to earbuds%d speaker\n", n, sco_data_in[read_index][0], sco_data_in[read_index][1], write_index);
		}
	}

	close(sock_fd[index]);
	quit = true;
	g_main_loop_quit(loop);

	return NULL;
}

// if not found return NUM_DEV
int get_index(const char *device_path)
{
  for (int i = 0; i < NUM_DEV; i++) {
    const char *path = th_args[i].path;
	  if (strcmp(device_path, path) == 0)
	    return i;
  }

	  return NUM_DEV;
}
static void handle_method_call(GDBusConnection *conn, const char *sender, const char *path, const char *interface,
		const char *method, GVariant *params, GDBusMethodInvocation *invocation, void *userdata)
{
  int index;

	int fd_handle;
	char *device_path;
	GError *error = NULL;
	GVariantIter *properties;
	GUnixFDList *fd_list;
	GDBusMessage *dbus_msg;

	printf("%s:%d \n", __func__, __LINE__);
	if (strcmp(method, "NewConnection") == 0) {
		g_variant_get(params, "(&oha{sv})", &device_path, &fd_handle, &properties);
    index = get_index(device_path);
    if (index >= NUM_DEV) {
      printf("%s:%d invalid index %d : %s\n", __func__, __LINE__, index, device_path);
      assert(0);
    }

    printf("%s:%d New connection from: [%d] %s\n", __func__, __LINE__, index, device_path);

		/* Retrieve file descriptor */
		dbus_msg = g_dbus_method_invocation_get_message(invocation);
		fd_list = g_dbus_message_get_unix_fd_list(dbus_msg);
		slc_fd[index] = g_unix_fd_list_get(fd_list, fd_handle, &error);
		g_assert_no_error(error);
		g_free(device_path);
		g_dbus_method_invocation_return_value(invocation, NULL);
		sem_post(&connected[index]); /* Signal to write thread that fd is available */
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
	pthread_t slc_thread[NUM_DEV];
	pthread_t sco_thread[NUM_DEV];
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
	for (int i = 0; i < 2; i++) {
    sem_init(&connected[i], 0, 0);
    printf("%s:%d i=%d\n", __func__, __LINE__, i);
    err = pthread_create(&slc_thread[0], NULL, &slc_thread_func, (void *) &th_args[i]);
    assert(err == 0);
  }

//  printf("%s:%d \n", __func__, __LINE__);
//  err = pthread_create(&slc_thread[1], NULL, &slc_thread_func2, NULL);
//  assert(err == 0);

  for (int i = 0; i < 2; i++) {
    /* Create thread for opening SCO connection and sending sine wave audio out */
    sem_init(&slc_established[i], 0, 0);
    printf("%s:%d i=%d\n", __func__, __LINE__, i);
    err = pthread_create(&sco_thread[i], NULL, &sco_thread_func, (void *) &th_args[i]);
    assert(err == 0);
  }

	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
	for (int i = 0; i < 2; i++) {
    pthread_join(slc_thread[i], NULL);
    pthread_join(sco_thread[i], NULL);
  }
	g_main_loop_unref(loop);
	g_object_unref(conn);
	printf("Profile client stopped\n");

	return 0;
}
