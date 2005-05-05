#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include "gradm.h"

#define PAM_SERVICENAME "gradm"

int gradm_pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	int i;
	struct pam_response *response;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	response = malloc(num_msg * sizeof(struct pam_response));
	if (response == NULL)
		return PAM_CONV_ERR;
	for (i = 0; i < num_msg; i++) {
		response[i].resp_retcode = 0;
		response[i].resp = 0;
		switch (msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_ON:
				fputs(msg[i]->msg, stdout);
				response[i].resp = calloc(1, PAM_MAX_RESP_SIZE);
				fgets(response[i].resp, PAM_MAX_RESP_SIZE, stdin);
				*(response[i].resp + strlen(response[i].resp) - 1) = '\0';
				break;
			case PAM_PROMPT_ECHO_OFF:
				response[i].resp = strdup(getpass(msg[i]->msg));
				break;
			case PAM_ERROR_MSG:
				fputs(msg[i]->msg, stderr);
				break;
			case PAM_TEXT_INFO:
				fputs(msg[i]->msg, stdout);
				break;
			default:
				if (response)
					free(response);
				return PAM_CONV_ERR;
		}
	}

	*resp = response;

	return PAM_SUCCESS;
}

int main(int argc, char *argv[])
{
	pam_handle_t *pamh = NULL;
	int retval;
	struct pam_conv conv = { gradm_pam_conv, NULL };
	struct gr_arg_wrapper wrapper;
	struct gr_arg arg;
	int fd;

	if (argc != 2)
		exit(EXIT_FAILURE);

	wrapper.version = GRADM_VERSION;
	wrapper.size = sizeof(struct gr_arg);
	wrapper.arg = &arg;
	arg.mode = GRADM_STATUS;

	if ((fd = open(GRDEV_PATH, O_WRONLY)) < 0) {
		fprintf(stderr, "Could not open %s.\n", GRDEV_PATH);
		failure("open");
	}

	retval = write(fd, &wrapper, sizeof(struct gr_arg_wrapper));
	close(fd);

	if (retval != 1)
		exit(EXIT_FAILURE);
	
	retval = pam_start(PAM_SERVICENAME, argv[1], &conv, &pamh);

	if (retval == PAM_SUCCESS)
		retval = pam_authenticate(pamh, 0);

	if (retval == PAM_SUCCESS)
		retval = pam_acct_mgmt(pamh, 0);

	if (retval == PAM_AUTHTOK_EXPIRED)
		retval = pam_chauthtok(pamh, 0);

	if (pamh)
		pam_end(pamh, retval);

	if (retval != PAM_SUCCESS)
		exit(EXIT_FAILURE);

	return EXIT_SUCCESS;
}
