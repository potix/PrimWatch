#ifndef TCP_SERVER_H
#define TCP_SERVER_H

typedef struct tcp_server tcp_server_t;

/*
 * tcpサーバーを開始するevent_baseに対してeventを登録する 
 * この関数の後にevent_dispatch等を行う必要がある                   
 */ 
int tcp_server_start(
    tcp_server_t **tcp_server,
    struct event_base *event_base,
    const char *addr,
    const char *port,
    int (*on_recv_line_cb)(char **result, size_t *result_len, char *line, void *on_recv_line_cb_arg),
    void *on_recv_line_cb_arg);

/*
 *  tcpサーバーを止める
 */
int tcp_server_stop(
    tcp_server_t *tcp_server);

#endif
