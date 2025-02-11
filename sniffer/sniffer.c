#include <stdio.h>
#include <string.h> // memset
#include <stdlib.h> // exit
#include <unistd.h> // getopt
#include <signal.h> // Ctrl+C handling
#include <arpa/inet.h> // struct in_addr
#include <time.h> // ctime
#include <pcap.h> // libpcap
#include <stdbool.h> // bool
#include <hiredis/hiredis.h>
#include "datagram.h"
#include "ethernetframe.h"
#include "ippacket.h"
#include "arppacket.h"
#include "sniffer.h"
#include "tuple.h"
#include "utils.h"
#include "ipaddress.h"
#include "simple-set.h"
#include "pingflooddetector.h"
#include "tcpsessiontracker.h"
#include "tftp.h"
#include "tftpsessiontracker.h"

pcap_t *pcap_session = NULL;   // libpcap session handle
char *strfilter = NULL;        // textual BPF filter
struct bpf_program binfilter;  // compiled BPF filter program
pcap_dumper_t *logfile = NULL; // file descriptor for datagram logging
bool show_raw = false;         // deactivate raw display of data captured
bool quiet_mode = false;       // control whether the callback display captured datagrams or not
int security_tool = 0;         // security tool to apply
unsigned int capture_count = 0;// count of captured datagrams 
char *tftpserver = NULL;       // supervised TFTP server
SimpleSet arpRequests = NULL;  // arp spoofing detector
pingflooddetector pingFloods = NULL;  // ping flood detector
tcpsessiontracker tcpSessions = NULL; // tcp sessions tracker
tftpsessiontracker tftpSessions = NULL; // tftp sessions tracker

//mutex & sniffer
struct sniff_list sniffer_list;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void sniff_list_handler(int signum)
{
	int i = 0;

	switch (signum) {
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			for (i = 0; i < sniff_conf.cpu_number; i++) {
				pthread_cancel(sniff_conf.thread[i]);
			}

            for (i = 0; i < sniff_conf.cpu_number; i++) {
                pthread_join(sniff_conf.thread[i], NULL);
			}

			free(sniff_conf.thread);
			sniff_list_destroy();
			break;
	}
}

void init_config(const char *argv0)
{
	const char *cp = NULL;
	sniff_conf.cpu_number = sysconf(_SC_NPROCESSORS_ONLN);
	sniff_conf.thr_number = sniff_conf.cpu_number - 1;

	if ((cp = strrchr(argv0, '/')) != NULL)
		sniff_conf.program_name = cp + 1;
	else
		sniff_conf.program_name = argv0;

	sniff_conf.thread = (pthread_t *) malloc(sniff_conf.thr_number * sizeof(pthread_t));
	if (sniff_conf.thread == NULL) 
		error("malloc failed.\n");
}

void *send_redis_handler(void *arg)
{
	char ip_src[MAXINUM_ADDR_LENGTH] = "";
	char ip_dst[MAXINUM_ADDR_LENGTH] = "";
    char buf[128] = "";
    char redis_list_name[32] = "pcap_sniff_info";
	char *addr_buf = NULL;
	redisContext *context = NULL;
	redisReply *reply = NULL; 
	int ret = 0;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	/* Initialize redis client */
	context = redisConnect("127.0.0.1", 6379);
	if (context->err) {
		error("Connect to redis server failed.\n");
	}

	reply = (redisReply *)redisCommand(context, "AUTH 123456");
	if (reply->type == REDIS_REPLY_ERROR) {
		error("Redis Authentication failed!\n");
	} else {
		printf("Redis Authentication succeed! \n");
	}
	freeReplyObject(reply);

	while (1) {
		reply = NULL;
		struct sniff_tuple info;
        ret = sniff_list_pull(&info);
		if (ret != SUCCESS) {
			continue;
		}

        sprintf(buf, "%s:%d<->%s,%d,%u,%d", info.src,info.src_port,info.dst,info.dst_port,info.tv_sec, info.pkt_cnt);

		reply = (redisReply *)redisCommand(context, "LPUSH %s %s", redis_list_name, buf);
        //reply = (redisReply *)redisCommand(context, "INCRBY %s %u", buf,  info.pkt_cnt);
		if (reply == NULL) {
            redisFree(context);
			error("execute redis command failed.\n");
		}

        if(!quiet_mode)
            printf("reply is %d ;INCRBY %s, %s, %u, %u\n", reply->type, info.src,  info.dst,  info.src_port,  info.dst_port);
		
        freeReplyObject(reply);
	}

	redisFree(context);
	pthread_exit(NULL);
}

int start_thread(void)
{
	pthread_t *thread = sniff_conf.thread;
	uint32_t thr_number = sniff_conf.thr_number;
	int i = 0; 

	for (i = 0; i < thr_number; i++)
		pthread_create(&thread[i], NULL, send_redis_handler, NULL);

	return 0;
}

// Function releasing all resources before ending program execution
static void shutdown_sniffer(int error_code) {
    // close the trackers
    destroy_trackers();
    // close log file
    if (logfile != NULL) {
        pcap_dump_close(logfile);
    }
    // Destroy compiled BPF filter if need
    if (strfilter != NULL) {
        pcap_freecode(&binfilter);
    }
    // close libpcap session
    if (pcap_session != NULL) {
        pcap_close(pcap_session);
    }
    printf("*** %d datagrams captured.\n", capture_count);
    exit(error_code);
}

// ctrl+c interrupt hanlder
void bypass_sigint(int sig_no) {
    printf("**\nCapture process interrupted by user...\n");
    shutdown_sniffer(0); // we're done
    sniff_list_handler(sig_no);
}

// Initialize the trackers
void initialize_trackers() {
    newSimpleSet(&arpRequests);
    newPingFloodDetector(&pingFloods);
    newTCPSessionTracker(&tcpSessions);
    newTFTPSessionTracker(&tftpSessions);
}

// Destroy the trackers
void destroy_trackers() {
    disposeSimpleSet(arpRequests);
    destroy_tcpsessiontracker(tcpSessions);
    destroy_pingflooddetector(pingFloods);
    destroy_tftpsessiontracker(tftpSessions);
}

// callback given to pcap_loop() fro processing captural datagrams
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    struct sniff_tuple tuple_info;
    memset(&tuple_info, 0, sizeof(struct sniff_tuple));
    if(!quiet_mode)
        printf("===Grabbed %d bytes (%d%%) of datagram, received on %s\n", 
            h->caplen, 
            (int)(100.0 * h->caplen / h->len), 
            ctime((const time_t*)&h->ts.tv_sec)
            );
    
    tuple_info.tv_sec = h->ts.tv_sec;
    // create datagram instance
    datagram *d = new_datagram(packet, h->caplen);
    if (show_raw) {
        if(!quiet_mode) d->print_datagram(d);
    }

    if(!quiet_mode)
        printf("---------- Begin to analyze this frame ----------\n");
    
    // create ethernetframe instance
    ethernetframe *e = d->create_ethernetframe(d);
    if(!quiet_mode) printf("---------- Ethernet frame header ----------\n");
    if(!quiet_mode) e->print_ethernetframe(e);
    
    // release the allocated memory not used anymore
    free(d);

    // Display payload content according to EtherType
    switch(e->ether_type(e)) {
        case et_IPv4: {
            // create ippacket instance
            ippacket *i = e->create_ippacket(e);
            if(!quiet_mode) printf("-------- IP packet header --------\n");
            if(!quiet_mode) i->print_ippacket(i);
            
            //fill the src & dst ip
            sprintf(tuple_info.src, "%s", get_ipaddress(i->source_ip(i)));
            if(!quiet_mode) printf("tuple_info.src : %s\n", get_ipaddress(i->source_ip(i)) );
            sprintf(tuple_info.dst, "%s", get_ipaddress(i->destination_ip(i)));
            if(!quiet_mode) printf("tuple_info.dst : %s\n", get_ipaddress(i->destination_ip(i)) );
            
            // If it's an ICMP packet, display its attributes
            if (i->protocol(i) == ipp_icmp) {
                icmppacket *icmp = i->create_icmppacket(i);
                if(!quiet_mode) printf("----- ICMP packet header -----\n");
                if(!quiet_mode) icmp->print_icmppacket(icmp);
                
                // Apply ping flood detection if required
                if (security_tool == PINGFLOOD && pingFloods->process_ping(i->destination_ip(i), icmp, pingFloods)) {
                    printf("\n **** ALERT - Poetential ping flood detected **** \n"); 
                    printf("      numerous echo requests with large payload targeting \n");
                    printf("      host %s\n", get_ipaddress(i->destination_ip(i)));
                }

                // release allocated memory
                free(icmp);
            }
            else if (i->protocol(i) == ipp_tcp) {// if  it transports a TCP segment, display its attribute
                tcpsegment *tcp = i->create_tcpsegment(i);
                if(!quiet_mode) printf("----- TCP segment header -----\n");
                if(!quiet_mode) tcp->print_tcpsegment(tcp);
                
                //fill the src dst port
                tuple_info.src_port = tcp->src_port(tcp);
                tuple_info.dst_port = tcp->dst_port(tcp);

                // Apply TCP session tracking if required
                if(security_tool == TCPTRACK) {
                    tcpSessions->process_tcpsegment(i, tcpSessions);     
                }

                //push to tuple_info
                sniff_list_push(tuple_info);
                
                // release allocated memory
                free(tcp);
            } 
            else if (i->protocol(i) == ipp_udp) {// if it transports a UDP segment, display its attributes
                udpsegment *udp = i->create_udpsegment(i);
                if(!quiet_mode) printf("----- UDP segment header -----\n");
                if(!quiet_mode) udp->print_udpsegment(udp);

                //fill the src dst port
                tuple_info.src_port = udp->source_port(udp);
                tuple_info.dst_port = udp->destination_port(udp);

                // If it is a TFTP message, display its attributes
                if (security_tool == TFTPTRACK && tftpserver) {
                    tftpSessions->process_tftpmessage(i, tftpserver, tftpSessions);
                }

                //push to tuple_info
                sniff_list_push(tuple_info);

                //release allocated memory
                free(udp);                 
            }


            // release allocated memory
            free(i);
            break;
        }
        case et_ARP: {
            // create arppacket instance
            arppacket *a = e->create_arppacket(e);
            if(!quiet_mode) printf("--------- ARP packet header--------\n");
            if(!quiet_mode) a->print_arppacket(a);
            // Check if we must apply ARP spoofing detection
            if (security_tool == ARPSPOOF) {
                switch(a->operation(a)) {
                    case akt_ArpRequest:
                        // Add target's IP to the set to log there was a request to its MAC
                        printf("arp request destination ip : %s\n", get_ipaddress(a->destination_ip(a)));
                        arpRequests->add(get_ipaddress(a->destination_ip(a)), arpRequests);
                        break;
                    case akt_ArpReply:
                        // Make sure the source respond to a legitimate request
                        if (arpRequests->find(get_ipaddress(a->source_ip(a)), arpRequests) == -1) {
                            // this reply is gratuitous(no corresponding request)
                            printf("\n **** ALERT - Poetential ARP spoofing detected **** \n");
                            printf("Unsollicited ARP reply to %s ,", get_macaddress(a->destination_mac(a)));
                            printf("originating from %s.", get_macaddress(a->source_mac(a)));
                        } else {
                            arpRequests->removeElement(get_ipaddress(a->source_ip(a)), arpRequests);
                        }
                        break;
                }
            }
            // release allocated memory
            free(a);
            break;
        }
            
    } 
    
    // release allocated memory
    free(e);

    // log datagram if required
    if (user != NULL) {
        pcap_dump(user, h, packet);
    }
    // Count the capture
    capture_count++;
}

static char* fetch_device(char *errbuf) {
    pcap_if_t *ift = NULL;
    char *dev = NULL;
    if(pcap_findalldevs(&ift, errbuf) == 0) {
        if(ift) {
            dev = malloc(sizeof(char) * (strlen(ift->name) + 1));
            strcpy(dev, ift->name);
        }
        pcap_freealldevs(ift);
    } else {
        fprintf(stderr, "error: %s\n", errbuf);
    }
    return dev;
}

int main(int argc, char *argv[]) {
    char *device = NULL;  // device to sniff
    char argch;           // to manage command line arguments
    char errbuf[PCAP_ERRBUF_SIZE];        // to handle libpcap error message
    int  siz = 1518,    // max number of bytes captured for each datagram
         promisc = 0,    // deactive promiscuous mode?? promiscuous mode??
         cnt = -1;       // capture indefinitely
    char *wlogfname = NULL, // filename where to log captured datagrams
         *rlogfname = NULL; // filename from which to read logged datagrams 


    // install ctrl+c handle
    struct sigaction sa, osa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler  = &bypass_sigint;
    sigaction(SIGINT, &sa, &osa);

    while((argch = getopt(argc, argv, "hpqrd:f:i:l:n:s:S:")) != EOF) {
        switch(argch) {
            case 'd': // device name
                device = optarg;
                break;
            case 'f': // BPF filter
                strfilter = optarg;
                break;
            case 'h':
                printf("Usage: sniffer [-d XXX -h]\n");
                printf("-d XXX: device to capture from, where XXX is device name (ex: eth0).\n");
                printf("-f 'filter' : filter captures according to BPF expression (ex: 'ip or arp'). \n");
                printf("-h : show this information.\n");
                printf("-i file: read datagram from given file instead of a device.\n");
                printf("-l file: log captured datagrams in given file.\n");
                printf("-n : number of datagrams to capture.\n");
                printf("-p : active promiscuous capture mode.\n");
                printf("-q : active quite mode. \n");
                printf("-r : active raw display of captured data.\n");
                printf("-s: apply specified security application. Available applications: arpspoof, pingflood, tcptrack, tftptrack.\n");
                printf("-S #.#.#.# : IP address of TFTP server to monitor.\n");
                if (argc == 2) return 0;
                break;
            case 'i': // filename from which to read logged datagram
                rlogfname = optarg;
                break;
            case 'l': // filename where to log captured datagrams
                wlogfname = optarg;
                break;
            case 'n': // number of datagrams to capture
                cnt = atoi(optarg);
                break;
            case 'p':
                promisc = 1;
                break;
            case 'r': // active raw display of captured data
                show_raw = 1;
                break;
            case 'q': // active quiet mode
                quiet_mode = 1;
                break;
            case 's': // apply specified security tool
                if(!strcmp(optarg, "arpspoof")) { // strcmp return 0 when two string are equal
                    security_tool = ARPSPOOF;
                } else if (!strcmp(optarg, "pingflood")) {
                    security_tool = PINGFLOOD;
                } else if (!strcmp(optarg, "tcptrack")) {
                    security_tool = TCPTRACK;
                } else if (!strcmp(optarg, "tftptrack")) {
                    security_tool = TFTPTRACK;
                }
                else {
                    fprintf(stderr, "error = unknown security tool specified (%s)\n", optarg);
                    return -10;
                }
                break;
            case 'S': // TFTP server to monitor
                tftpserver = optarg; 
                break;
        }
    }
    // option -d and -i are mutually exclusives
    if (device != NULL && rlogfname != NULL) {
        fprintf(stderr, "error - options -d and -i are mutually exclusives\n");
        return -7;
    }
    // Option S is exclusively usable for TFTP server monitoring
    if (tftpserver != NULL && security_tool != TFTPTRACK) {
       fprintf(stderr, "error - option S may be used only for TFTP tracking \n");
       return -11;
    }
    // Make sure the IP of a TFTP server was specified for monitoring
    if (security_tool == TFTPTRACK && tftpserver == NULL) {
        fprintf(stderr, "error - no TFTP server specified (use option -S)\n");
        return -11;
    }

    // identify device to use
    if (device == NULL && rlogfname == NULL) {
        if ((device = fetch_device(errbuf)) == NULL) {
            fprintf(stderr, "error - %s\n", errbuf);
            return -2;
        }
    }  

    if (rlogfname != NULL) {
        printf("input file = %s\n", rlogfname);
    } else {
        printf("device = %s %s\n", device, promisc ? " (promiscuous)": "");
    }

    // extract IP informaiton for network connected to device
    bpf_u_int32 netp,   // ip address of network
                maskp;  // network mask
    if ((pcap_lookupnet(device, &netp, &maskp, errbuf)) == -1) {
        fprintf(stderr, "error - %s\n", errbuf);
        return -3;
    }

    // translate ip address into textual form for display
    struct in_addr addr;
    char *net;
    addr.s_addr = netp;
    if ((net = inet_ntoa(addr)) == NULL) {
        fprintf(stderr, "error - inet_ntoa() failed");
    } else {
        printf("network ip = %s\n", net);
    }

    // Translate network mask into textual for for display
    char *mask;
    addr.s_addr = maskp;
    if ((mask = inet_ntoa(addr)) == NULL) {
        fprintf(stderr, "error - inet_ntoa() failed\n");
    } else {
        printf("network mask = %s\n", mask);
    }

    // Open a libpcap capture session
    if (rlogfname == NULL) {
        // session linked to the device
        pcap_session = pcap_open_live(device, siz, promisc, 1000, errbuf);
        if (pcap_session == NULL) {
            fprintf(stderr, "error - pcap_open_live() failed: %s\n", errbuf);
            return -4;
        }
    } else {
        // session linked to the log file
        pcap_session = pcap_open_offline(rlogfname, errbuf);
        if (pcap_session == NULL) {
            fprintf(stderr, "error - pcap_open_offline() failed: %s\n", errbuf);
        }
    }
    // Compile BPF filter expression into program if one provided
    if (strfilter != NULL) {
        // compile filter expression
        if (pcap_compile(pcap_session, &binfilter, strfilter, 1, maskp) < 0) {
            fprintf(stderr, "error - pcap_compile() failed (%s)\n", pcap_geterr(pcap_session));
            shutdown_sniffer(-5); 
        }

        // install compiled filter
        if (pcap_setfilter(pcap_session, &binfilter) < 0) {
            fprintf(stderr, "error - pcap_setfilter() failed (%s)\n", pcap_geterr(pcap_session));
            shutdown_sniffer(-6);
        }

        printf("BPF filter = %s\n", strfilter);
    }
    
    // captured datagrams logged 
    if(wlogfname != NULL) {
        if((logfile = pcap_dump_open(pcap_session, wlogfname)) == NULL) {
            fprintf(stderr, "error - pcap_dumpj_open() failed (%s)\n", pcap_geterr(pcap_session));
            shutdown_sniffer(-9);
        }
    }
    
    // Display any security application enabled
    switch(security_tool) {
        case ARPSPOOF: 
            printf("ARP spoofing detection enabled...\n");
            break;
        case PINGFLOOD:
            printf("Ping flood detection enabled...\n");
            break;
        case TCPTRACK:
            printf("TCP session track enabled..\n");
            break;
    }

    // release allocated memory
    // free(device);

    // initialization of trackers
    initialize_trackers();

    /* initialize config */
	init_config(argv[0]);
    
    // initialization of tuple_list
    sniff_list_init();

    /* start thread sended redis command */
	start_thread();

    // Start capturing
    pcap_loop(pcap_session, cnt, process_packet, (u_char *)logfile);

        
    shutdown_sniffer(0);

}
