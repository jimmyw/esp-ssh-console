typedef void (*ssh_shell_func_t)(void *ctx);

typedef struct {
    ssh_shell_func_t shell_func;
    void *shell_func_ctx;
    uint32_t shell_task_size;
    const char *bindaddr;
    const char *port;
} ssh_server_config_t;

void ssh_server_start(ssh_server_config_t *config);