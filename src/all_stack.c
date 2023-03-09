#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <malloc.h>

#include "all_stack.h"
#include "all_stack.skel.h"

int count = 0;
int count_i = 0;
int sport,dport;

static volatile bool exiting = false;
bool verbose = false;

const char *time_name[]={"eth_type_trans","ip_rcv","ip_rcv_finish","tcp_v4_rcv","",""};

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}


static int handle_event(void *ctx,void *data, size_t data_sz)
{
    const struct netstack_info *d = data;
    char saddr[INET_ADDRSTRLEN],daddr[INET_ADDRSTRLEN];
    struct sockaddr_in sockaddr;
    sockaddr.sin_addr.s_addr = d->pkt_tuple.saddr;
    inet_ntop(AF_INET, &sockaddr.sin_addr, saddr, sizeof(saddr));
    sockaddr.sin_addr.s_addr = d->pkt_tuple.daddr;
    inet_ntop(AF_INET, &sockaddr.sin_addr, daddr, sizeof(daddr));
    printf("cpu:%d,source:%s:%d,dest:%s:%d,seq:%u,ack:%u\n",
        d->pkt_tuple.cpu,
        saddr,
        d->pkt_tuple.sport,
        daddr,
        d->pkt_tuple.dport,
        d->pkt_tuple.seq,
        d->pkt_tuple.ack);
    printf("%-25s %f\n",time_name[0],d->time_info[0]*1e-9);
    for(int i=1;i<max_trace_func;i++){
         if(i > sizeof(time_name) /sizeof(char *)-1) 
            break;
        if(d->time_info[i] == 0 || time_name[i][0] == 0)
            continue;
        printf("%-25s %f\n",time_name[i],d->time_info[i]*1e-9);
        //printf("%f (%d)",d->time_info[i]*1e-9,(d->time_info[i]-d->time_info[i-1])/1000);
    }
    printf("\n");
    return 0;
}

void test_data(){
    ;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
    struct all_stack_bpf *skel;
	int err = 0;
    test_data();
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = all_stack_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    /* Parameterize BPF code */
    skel->rodata->filter_dport = dport;
    skel->rodata->filter_sport = sport;

    /* Load & verify BPF programs */
	err = all_stack_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    /* Attach tracepoints */
	err = all_stack_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    /* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	all_stack_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}