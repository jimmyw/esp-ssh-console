
typedef struct {
    const char *prompt;
} ssh_server_config_t;

void ssh_server_start(ssh_server_config_t *config);