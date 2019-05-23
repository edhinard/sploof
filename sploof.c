#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <pthread.h>

/* =========================================================================== */
/* ================================ CONSTANTS ================================ */
/* =========================================================================== */
const char *usage = "sploof <target> [--spoof <origin>] [--tcp <sport> <dport> <flags>]|[--udp <sport> <dport>] [--payload <filename>] [--count <num>]\n";
const char *tagplaceholder = ".....";
const char *ipstringplaceholder = "xxx.xxx.xxx.xxx";
const char *portstringplaceholder = "ppppp";



/* =========================================================================== */
/* ================================== TYPES ================================== */
/* =========================================================================== */
struct params_t {
  char *spoof;
  char *target;
  in_addr_t src_ip;
  in_addr_t dst_ip;
  struct ether_addr src_mac;
  struct ether_addr dst_mac;
  int count;
  enum {
    RANDOM = 0,
    UDP = IPPROTO_UDP,
    TCP = IPPROTO_TCP,
  } protocol;
  union {
    struct {
      int sport;
      int dport;
    } udp;
    struct {
      int sport;
      int dport;
      int flags;
    } tcp;
  };
  char *payload;
  int payloadlen;
};

typedef struct {
  char *addr;
  union {
    struct {
      uint32_t deltaip;
    } spoof_src;
    struct {
      uint32_t ip;
      uint32_t deltaip;
    } random_ipstring;
    struct {
      uint16_t port;
      uint16_t deltaport;
    } random_port;
    struct {
      struct sploof_t *sploof;
    } tcp_checksum;
    uint8_t deltaproto;
    struct {
      uint32_t tagnum;
      uint32_t deltatagnum;
    } random_tag;
  };
}cbdata;

typedef void (*transformcb_ptr)(cbdata*);

struct cb_t {
  transformcb_ptr transformcb;
  cbdata data;
  struct cb_t *next;
};

struct sploof_t {
  char *begin;
  char *end;
  char buf[65535];
  int len;
  struct ether_header *eth;
  struct ip *ipv4;
  struct udphdr *udp;
  struct tcphdr *tcp;
  char *payload;
  
  int sock;
  struct sockaddr_ll sockaddr;
  
  struct cb_t *datacb;
  struct cb_t *checksumcb;

  int count;
  pthread_t thread;
  int running;
  unsigned long long packets;
};



/* =========================================================================== */
/* ================================ PROTOTYPES =============================== */
/* =========================================================================== */
void sighandler(int);
struct params_t *get_params(int, char*[]);
void error(const char *, ...);
void printkMGTP(float);
void printduration(long long);

struct sploof_t *sploof_init(struct params_t*);
void sploof_terminate(struct sploof_t*);
void sploof_registercb(struct cb_t**, transformcb_ptr, cbdata*);
void sploof_add_udp(struct sploof_t*, int, int);
void sploof_add_tcp(struct sploof_t*, int, int, int);
void sploof_add_payload(struct sploof_t*, char*, int);
void sploof_run(struct sploof_t*);

void ipv4_compute_checksum(cbdata*);
void tcp_compute_checksum(cbdata*);
void ipv4_spoof_src(cbdata*);
void ipv4_random_protocol(cbdata*);
void random_port(cbdata*);
void random_tag(cbdata*);
void random_ipstring(cbdata*);
void random_portstring(cbdata*);

void find_hw_addr(struct params_t *);




/* =========================================================================== */
/* =========================================================================== */
/* =========================================================================== */
int end = 0;
int main(int argc, char *argv[])
{
  struct params_t *params = get_params(argc, argv);
  struct sploof_t *sploof = sploof_init(params);
  int ret = pthread_create(&sploof->thread, NULL, (void*(*)(void*))sploof_run, sploof);
  if(ret != 0) {
    error("cannot launch thread. error value=%d", ret);
  }
  signal(SIGINT, sighandler);

  /* periodically display statistics */
  fprintf(stderr, "\n-----------------------------------------------------------\n");
  struct timespec starttime;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &starttime); 
  struct timespec Atime = starttime;
  unsigned long long Apackets = 0;
  int s = 1;
  while(!end) {
    sleep(s);
    s *= 2;
    if(s>30) s=30;

    /* get number of sent packests and period duration */
    struct timespec Btime;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &Btime);
    unsigned long long Bpackets = sploof->packets;
    float deltatime = Btime.tv_sec - Atime.tv_sec + (Btime.tv_nsec - Atime.tv_nsec)/1000000000.;
    unsigned long long deltapackets = Bpackets - Apackets;
    unsigned long long deltabytes = deltapackets * sploof->len;
    Atime = Btime;
    Apackets = Bpackets;

    /* display */
    char currenttime[50];
    time_t t;
    t = time(NULL);
    strftime(currenttime, sizeof(currenttime), "%H:%M:%S", localtime(&t));
    fprintf(stderr,"\r   %s    ", currenttime);
    printkMGTP(deltapackets);
    fprintf(stderr,"p ");
    printkMGTP(deltapackets/deltatime);
    fprintf(stderr, "p/sec - ");
    printkMGTP(deltabytes);
    fprintf(stderr,"B ");
    printkMGTP(deltabytes/deltatime);
    fprintf(stderr, "B/sec\n");

    if(!sploof->running) {
      end = 1;
    }
  }

  /* summary */
  struct timespec stoptime;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &stoptime);
  fprintf(stderr, "-----------------------------------------------------------\n");
  float deltatime = stoptime.tv_sec - starttime.tv_sec + (stoptime.tv_nsec - starttime.tv_nsec)/1000000000.;
  printduration(deltatime);
  fprintf(stderr,"   ");
  printkMGTP(sploof->packets);
  fprintf(stderr,"p ");
  printkMGTP(sploof->packets/deltatime);
  fprintf(stderr, "p/sec - ");
  printkMGTP(sploof->packets*sploof->len);
  fprintf(stderr,"B ");
  printkMGTP(sploof->packets*sploof->len/deltatime);
  fprintf(stderr, "B/sec\n");
  
  sploof->running=0;
  pthread_join(sploof->thread, NULL);
  sploof_terminate(sploof);

  return(0);
}
void sighandler(int dummy)
{
  (void)dummy;
  end = 1;
}
void printkMGTP(float num)
{
  char *unit = "?";
  if(num > 1e15) {
    unit = "P";
    num /= 1e15;
  } else if(num > 1e12) {
    unit = "T";
    num /= 1e12;
  } else if(num > 1e9) {
    unit = "G";
    num /= 1e9;
  } else if(num > 1e6) {
    unit = "M";
    num /= 1e6;
  } else if(num > 1e3) {
    unit = "k";
    num /= 1e3;
  } else {
    unit = "";
  }
  int frac = (int)(num*10) % 10;
  int ent = (int)num;
  fprintf(stderr, "%3d,%d%s", ent, frac, unit);
}
void printduration(long long duration)
{
  int days = duration / (24 * 3600);
  duration -= days * (24 * 3600);
  int hours = duration / 3600;
  duration -= hours * 3600;
  int minutes = duration / 60;
  duration -= minutes * 60;
  int seconds = duration;
  if(days) {
    fprintf(stderr, "%2dd", days);
  } else {
    fprintf(stderr, "   ");
  }
  fprintf(stderr, "%02dh%02dm%02ds", hours, minutes, seconds);
}


struct params_t *get_params(int argc, char *argv[])
{
  static struct params_t params = {
    .spoof = 0,
    .target = 0,
    .src_mac = {.ether_addr_octet={0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    .dst_mac = {.ether_addr_octet={0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    .count = 0,
    .protocol = RANDOM,
    .payload = 0,
    .payloadlen = 0,
  };

  /* parsing command line arguments */
  argc--;
  (void)*argv++;
  while(argc) {
    if(argv[0][0] != '-') {
      if(params.target) {
        error("$unexpected argument %s", argv[0]);
      }
      if(!inet_pton(AF_INET, argv[0], &params.dst_ip)) {
        error("$%s is not a valid IPv4 address", argv[0]);
      }
      params.target = argv[0];
    }

    else if(strcmp(argv[0], "--spoof") == 0) {
      argc--;
      (void)*argv++;
      if(!argc || argv[0][0] == '-') {
        error("$missing --spoof value");
      }
      if(!inet_pton(AF_INET, argv[0], &params.src_ip)) {
        error("$%s is not a valid IPv4 address", argv[0]);
      }
      params.spoof = argv[0];
    }

    else if(strcmp(argv[0], "--count") == 0) {
      argc--;
      (void)*argv++;
      if(!argc || argv[0][0] == '-') {
        error("$missing --count value");
      }
      params.count = atoi(argv[0]);
    }

    else if(strcmp(argv[0], "--payload") == 0) {
      argc--;
      (void)*argv++;
      if(!argc || argv[0][0] == '-') {
        error("$missing --payload value");
      }
      FILE *f = fopen(argv[0], "rb");
      if(!f) {
        error("$cannot open file %s", argv[0]);
      }
      fseek(f, 0, SEEK_END);
      params.payloadlen = ftell(f);
      fseek(f, 0, SEEK_SET);
      params.payload = malloc(params.payloadlen);
      if(!params.payload) {
        error("not enough memory for payload");
      }
      int unused = fread(params.payload, params.payloadlen, 1, f);
      (void)unused;
      fclose(f);
    }

    else if(strcmp(argv[0], "--udp") == 0) {
      argc--;
      (void)*argv++;
      if(argc<2 || argv[0][0] == '-' || argv[1][0] == '-') {
        error("$missing --udp values");
      }
      params.protocol = UDP;
      params.udp.sport = atoi(argv[0]);
      params.udp.dport = atoi(argv[1]);
      argc--;
      (void)*argv++;
    }

    else if(strcmp(argv[0], "--tcp") == 0) {
      argc--;
      (void)*argv++;
      if(argc<3 || argv[0][0] == '-' || argv[1][0] == '-' || argv[2][0] == '-') {
        error("$missing --tcp values");
      }
      params.protocol = TCP;
      params.tcp.sport = atoi(argv[0]);
      params.tcp.dport = atoi(argv[1]);
      for(char *p=argv[2]; *p; p++) {
        const char* FLAGS = "FSRPAUEC";
        char *i = index(FLAGS, *p);
        if(i==0) {
          error("$bad flag value %c", *p);
        }
        params.tcp.flags |= 1<<(i-FLAGS);
      }
      argc-=2;
      (void)*argv++;
      (void)*argv++;
    }

    else {
        error("$unexpected argument %s", argv[0]);
    }
    
    argc--;
    (void)*argv++;
  }

  /* target is a mandatory argument */
  if(!params.target) {
    error("$missing ip");
  }
  fprintf(stderr, "target=<%s>\n", params.target);
  

  /* find mac addresses: local interface and gateway */
  find_hw_addr(&params);

  return(&params);
}

void error(const char *error, ...)
{
  int print_usage = 0;
  va_list ap;
  va_start(ap, error);

  if(error[0] == '$') {
    print_usage = 1;
    error++;
  }
  vfprintf(stderr, error, ap);
  fprintf(stderr, "\n");
  if(print_usage) {
    fprintf(stderr, usage, "");
  }
  va_end(ap);
  exit(1);
}



/* =========================================================================== */
/* ============================== SPLOOF OBJECT ============================== */
/* =========================================================================== */
struct sploof_t *sploof_init(struct params_t *params)
{
  /* initialize random */
  srandom(getpid());

  /* allocate memory */
  struct sploof_t *sploof = (struct sploof_t*)malloc(sizeof(struct sploof_t));
  if(!sploof) {
    error("not enough memory for a sploof");
  }
  memset(sploof, 0, sizeof(struct sploof_t));

  /* prepare raw socket */
  sploof->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sploof->sock <= 0) {
    error("cannot create raw socket. %s", strerror(errno));
  }
  int ifindex = 2;
  memset((void *)&sploof->sockaddr, 0, sizeof(struct sockaddr_ll));
  sploof->sockaddr.sll_ifindex = ifindex;
  sploof->sockaddr.sll_halen = ETH_ALEN;
  memcpy(sploof->sockaddr.sll_addr, &params->dst_mac, ETH_ALEN);

  /* prepare Ethernet header */
  sploof->begin = (char*)&sploof->buf[0];
  sploof->eth = (struct ether_header*)sploof->begin;
  memcpy(sploof->eth->ether_shost, &params->src_mac, ETH_ALEN);
  memcpy(sploof->eth->ether_dhost, &params->dst_mac, ETH_ALEN);
  sploof->eth->ether_type = htons(ETHERTYPE_IP);

  /* prepare IPv4 header */
  sploof->ipv4 = (struct ip*)(&sploof->eth[1]);
  sploof->ipv4->ip_hl = 5;
  sploof->ipv4->ip_v = 4;
  sploof->ipv4->ip_tos = 0;
  sploof->ipv4->ip_len = htons(sizeof(struct ip));
  sploof->ipv4->ip_id = random();
  sploof->ipv4->ip_off = 0;
  sploof->ipv4->ip_ttl = 64;
  sploof->ipv4->ip_p = params->protocol;
  sploof->ipv4->ip_src.s_addr = params->src_ip;
  sploof->ipv4->ip_dst.s_addr = params->dst_ip;
  sploof->ipv4->ip_sum = 0;

  /* register IPv4 checksum calculation callback */
  /* first registered callback == the last to be called */
  {
    cbdata data = {.addr = (char*)sploof->ipv4};
    sploof_registercb(&sploof->checksumcb, &ipv4_compute_checksum, &data);
  }

  /* register IPv4 src address spoof callback */
  if(params->src_ip == 0) {
    cbdata data = {.addr = (char*)&sploof->ipv4->ip_src, .spoof_src.deltaip = random() | 0x0001};
    sploof_registercb(&sploof->datacb, &ipv4_spoof_src, &data);
  }

  /* register IPv4 protocol randomization callback */
  if(params->protocol == RANDOM) {
    cbdata data = {.addr = (char*)&sploof->ipv4->ip_p, .deltaproto = random() | 0x0001};
    sploof_registercb(&sploof->datacb, &ipv4_random_protocol, &data);
  }

  /* addition of udp, tcp or payload */
  sploof->end = (char*)(&sploof->ipv4[1]);
  sploof->len = sploof->end - sploof->begin;
  if(params->protocol == UDP) {
    sploof_add_udp(sploof, params->udp.sport, params->udp.dport);
  } else if(params->protocol == TCP) {
    sploof_add_tcp(sploof, params->tcp.sport, params->tcp.dport, params->tcp.flags);
  }
  if(params->payload) {
    sploof_add_payload(sploof, params->payload, params->payloadlen);
  }  

  sploof->count = params->count;
  sploof->running = 1;
  
  return(sploof);
}

void sploof_terminate(struct sploof_t *sploof)
{
  close(sploof->sock);
  struct cb_t *cb = sploof->datacb;
  while(cb) {
    struct cb_t *next = cb->next;
    free(cb);
    cb = next;
  }
  free(sploof);
}

void sploof_registercb(struct cb_t **firstcb, transformcb_ptr transformcb, cbdata *data)
{
  struct cb_t *cb = (struct cb_t*)malloc(sizeof(struct cb_t));
  if(!cb) {
    error("not enough memory for a callback");
  }
  cb->transformcb = transformcb;
  memcpy(&cb->data, data, sizeof(cbdata));
  cb->next = *firstcb;
  *firstcb = cb;
}

void sploof_add_udp(struct sploof_t *sploof, int sport, int dport)
{
  assert(!sploof->tcp);

  /* update IP */
  sploof->ipv4->ip_len = htons(ntohs(sploof->ipv4->ip_len) + sizeof(struct udphdr));

  /* prepare UDP header */
  sploof->udp = (struct udphdr*)sploof->end;
  if(sport != 0) {
    sploof->udp->uh_sport = htons(sport);
  } else {
    cbdata data = {.addr = (char*)&sploof->udp->uh_sport, .random_port.deltaport = random() | 0x0001};
    sploof_registercb(&sploof->datacb, &random_port, &data);
  }
  sploof->udp->uh_dport = htons(dport);
  sploof->udp->uh_ulen = htons(sizeof(struct udphdr));
  sploof->udp->uh_sum = 0;
  
  /* make ready for addition of payload */
  sploof->end = (char*)(&sploof->udp[1]);
  sploof->len = sploof->end - sploof->begin;
}

void sploof_add_tcp(struct sploof_t *sploof, int sport, int dport, int flags)
{
  assert(!sploof->udp);

  /* update IP */
  sploof->ipv4->ip_len = htons(ntohs(sploof->ipv4->ip_len) + sizeof(struct tcphdr));

  /* prepare TCP header */
  sploof->tcp = (struct tcphdr*)sploof->end;
  if(sport != 0) {
    sploof->tcp->th_sport = htons(sport);
  } else {
    cbdata data = {.addr = (char*)&sploof->tcp->th_sport, .random_port.deltaport = random() | 0x0001};
    sploof_registercb(&sploof->datacb, &random_port, &data);
  }
  sploof->tcp->th_dport = htons(dport);
  sploof->tcp->th_off = 5;
  sploof->tcp->th_flags = flags;
  {
    cbdata data = {.addr = (char*)sploof->tcp, .tcp_checksum.sploof = sploof};
    sploof_registercb(&sploof->checksumcb, &tcp_compute_checksum, &data);
  }
  
  /* make ready for addition of payload */
  sploof->end = (char*)(&sploof->tcp[1]);
  sploof->len = sploof->end - sploof->begin;
}

void sploof_add_payload(struct sploof_t *sploof, char *payload, int len)
{
  assert(!sploof->payload);
  
  /* update IP */
  int iplen = ntohs(sploof->ipv4->ip_len);
  if(iplen + len > 1500) {
    len = 1500-iplen;
    fprintf(stderr, "warning payload too long, truncated to %d bytes to fit in Ethernet frame\n", len);
  }
  sploof->ipv4->ip_len = htons(iplen + len);

  /* extend UDP length if any */
  if(sploof->udp) {
    sploof->udp->uh_ulen = htons(ntohs(sploof->udp->uh_ulen) + len);
  }

  /* copy payload */
  sploof->payload = sploof->end;
  memcpy(sploof->payload, payload, len);
  sploof->end += len;
  sploof->len = sploof->end - sploof->begin;

  char *tag = strstr(sploof->payload, tagplaceholder);
  while(tag) {
    cbdata data = {.addr = tag, .random_tag.tagnum = random(), .random_tag.deltatagnum = random() | 0x0001};
    sploof_registercb(&sploof->datacb, &random_tag, &data);
    tag = strstr(tag+strlen(tagplaceholder), tagplaceholder);
  }

  char *ipstring = strstr(sploof->payload, ipstringplaceholder);
  while(ipstring) {
    cbdata data = {.addr = ipstring, .random_ipstring.ip = random(), .random_ipstring.deltaip = random() | 0x0001};
    sploof_registercb(&sploof->datacb, &random_ipstring, &data);
    ipstring = strstr(ipstring+strlen(ipstringplaceholder), ipstringplaceholder);
  }

  char *portstring = strstr(sploof->payload, portstringplaceholder);
  while(portstring) {
    cbdata data = {.addr = portstring, .random_port.port = random(), .random_port.deltaport = random() | 0x0001};
    sploof_registercb(&sploof->datacb, &random_portstring, &data);
    portstring = strstr(portstring+strlen(portstringplaceholder), portstringplaceholder);
  }
}

void sploof_run(struct sploof_t *sploof)
{
  /* we do not want this thread to be interrupted by CTRL+C */
  sigset_t mask;
  sigemptyset(&mask); 
  sigaddset(&mask, SIGINT); 
  pthread_sigmask(SIG_BLOCK, &mask, NULL);

  /* chain datacbs and checksumcbs */
  if(sploof->datacb) {
    struct cb_t *cb = sploof->datacb;
    while(cb->next) {
      cb = cb->next;
    }
    cb->next = sploof->checksumcb;
  } else {
    sploof->datacb = sploof->checksumcb;
  }

  sploof->packets = 0;
  while(sploof->running) {
    /* apply change on buffer */
    struct cb_t *cb = sploof->datacb;
    while(cb) {
      cb->transformcb(&cb->data);
      cb = cb->next;
    }
    
    /* send buffer */
    sendto(sploof->sock, sploof->buf, sploof->len, 0, (struct sockaddr*)&sploof->sockaddr, sizeof(struct sockaddr_ll));
    sploof->packets++;
  
    if(sploof->count == sploof->packets) {
      sploof->running = 0;
    }
  }
}



/* =========================================================================== */
/* ================================ CALLBACKS ================================ */
/* =========================================================================== */
// from https://locklessinc.com/articles/tcp_checksum/
static inline unsigned short checksum2(const char *buf, unsigned size, unsigned long long init)
{
  unsigned long long sum = init;
  const unsigned long long *b = (unsigned long long *) buf;
  unsigned t1, t2;
  unsigned short t3, t4;

  /* Main loop - 8 bytes at a time */
  while (size >= sizeof(unsigned long long)) {
    unsigned long long s = *b++;
    sum += s;
    if (sum < s) sum++;
    size -= 8;
  }

  /* Handle tail less than 8-bytes long */
  buf = (const char *) b;
  if (size & 4) {
    unsigned s = *(unsigned *)buf;
    sum += s;
    if (sum < s) sum++;
    buf += 4;
  }
  if (size & 2) {
    unsigned short s = *(unsigned short *) buf;
    sum += s;
    if (sum < s) sum++;
    buf += 2;
  }
  if (size & 1) {
    unsigned char s = *(unsigned char *) buf;
    sum += s;
    if (sum < s) sum++;
  }

  /* Fold down to 16 bits */
  t1 = sum;
  t2 = sum >> 32;
  t1 += t2;
  if (t1 < t2) t1++;
  t3 = t1;
  t4 = t1 >> 16;
  t3 += t4;
  if (t3 < t4) t3++;

  return ~t3;
}

void ipv4_compute_checksum(cbdata *data)
{
  char *addr = data->addr;
  struct ip *ipv4 = (struct ip*)addr;
  volatile unsigned short *psum = &ipv4->ip_sum;
  *psum = 0;
  *psum = checksum2(addr, sizeof(struct ip), 0);
}
void tcp_compute_checksum(cbdata *data)
{
  struct tcphdr *tcp = (struct tcphdr*)data->addr;
  volatile unsigned short *psum = &tcp->th_sum;
  int len = data->tcp_checksum.sploof->end - data->addr;
  struct {
    in_addr_t src;
    in_addr_t dst;
    char zero;
    char proto;
    uint16_t len;
  } pseudo = {
    .src = data->tcp_checksum.sploof->ipv4->ip_src.s_addr,
    .dst = data->tcp_checksum.sploof->ipv4->ip_dst.s_addr,
    .zero = 0,
    .proto = 6,
    .len = htons(len)
  };
  *psum = 0;
  *psum = checksum2(data->addr, len, ~checksum2((char*)&pseudo, 12, 0));
}
void ipv4_spoof_src(cbdata *data)
{
  uint32_t *src = (uint32_t*)data->addr;
  *src += data->spoof_src.deltaip;
}
void ipv4_random_protocol(cbdata *data)
{
  uint8_t *proto = (uint8_t*)data->addr;
  *proto += data->deltaproto;
}
void random_port(cbdata *data)
{
  uint16_t *port = (uint16_t*)data->addr;
  *port += data->random_port.deltaport;
}
void random_tag(cbdata *data)
{
  char *tag = data->addr;
  data->random_tag.tagnum += data->random_tag.deltatagnum;
  /* tag is base64 encoding of lower 30 bits of tagnum */
  uint32_t num = data->random_tag.tagnum;
  for(int i=0; i<5; i++) {
    char code = num & 0x3f; /* 6 lower bits */
    if(code <= 25) {
      *tag++ = 'A' + code;
    } else if(code <= 51) {
      *tag++ = 'a' + code - 26;
    } else if(code <= 61) {
      *tag++ = '0' + code - 52;
    } else if(code == 62) {
      *tag++ = '+';
    } else {
      *tag++ = '!';
    }
    num >>= 6;
  }
}
void random_ipstring(cbdata *data)
{
  char *ipstring = data->addr;
  data->random_ipstring.ip += data->random_ipstring.deltaip;
  unsigned char *bytes = (unsigned char*)&data->random_ipstring.ip;

  for(int i=0; i<4; i++) {
    char lastchar = ipstring[4*i+3];
    sprintf(ipstring+4*i, "%03hu", bytes[i]);
    ipstring[4*i+3] = lastchar;
  }
}
void random_portstring(cbdata *data)
{
  char *portstring = data->addr;
  data->random_port.port += data->random_port.deltaport;

  char lastchar = portstring[5];
  sprintf(portstring, "%05hu", data->random_port.port);
  portstring[5] = lastchar;
}



/* =========================================================================== */
/* =========================================================================== */
/* =========================================================================== */
int rtnl_talk(struct nlmsghdr *, struct nlmsghdr **);
int rtnl_talk(struct nlmsghdr *request, struct nlmsghdr **answer)
{
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if(fd == -1) {
    error("cannot open RTNL socket. %s", strerror(errno));
  }
  if(!bind(fd, 0, 0)) {
    error("cannot bind RTNL socket. %s", strerror(errno));
  }

  int seq = time(NULL);
  request->nlmsg_pid = 0;
  request->nlmsg_seq = seq;
  request->nlmsg_flags |= NLM_F_ACK;

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  
  struct iovec iov = {
    .iov_base = request,
    .iov_len = request->nlmsg_len,
  };

  struct msghdr msg = {
    .msg_name = &sa,
    .msg_namelen = sizeof(sa),
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = 0,
    .msg_controllen = 0,
    .msg_flags = 0,
  };

  if(!sendmsg(fd, &msg, 0)) {
    error("cannot send to RTNL socket. %s", strerror(errno));
  }

  static char buf[8192];
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);
  int len = recvmsg(fd, &msg, 0);
  close(fd);

  *answer = (struct nlmsghdr *)buf;
  if((*answer)->nlmsg_seq != seq) {
    *answer = 0;
    return(0);
  }

  return(len);
}

#define NLMSG_TAIL(nmsg)                                                \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
void find_hw_addr(struct params_t *params)
{
  struct in_addr gw_ip = {0};
  int ifnum = 0;
  char buf[8192];
  memset(buf, 0, sizeof(buf));
  struct nlmsghdr *request = (struct nlmsghdr *)buf;

  /* Build GET ROUTE <ip> request */
  request->nlmsg_type = RTM_GETROUTE;
  request->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  request->nlmsg_flags = NLM_F_REQUEST;
  struct rtmsg *rtm = NLMSG_DATA(request);
  rtm->rtm_family = AF_INET;
  struct rtattr *rta;
  rta = NLMSG_TAIL(request);
  rta->rta_type = RTA_DST;
  rta->rta_len = RTA_LENGTH(4);
  memcpy(RTA_DATA(rta), &params->dst_ip, 4);
  request->nlmsg_len = NLMSG_ALIGN(request->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(4));

  struct nlmsghdr *answer;
  int nl_len = rtnl_talk(request, &answer);

  /* Parse GET ROUTE answer -> gw ip addr */
  int has_dst = 0;
  int has_gw = 0;
  struct in_addr dst_ip = {0};
  if(NLMSG_OK(answer, nl_len)) {
      
    struct rtmsg *rt_msg = (struct rtmsg *)NLMSG_DATA(answer);
    struct rtattr *rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
    int nd_len = RTM_PAYLOAD(answer);
    while (RTA_OK(rt_attr, nd_len)) {
      switch (rt_attr->rta_type) {
      case NDA_DST:
        has_dst = 1;
        memcpy(&dst_ip, RTA_DATA(rt_attr), sizeof(dst_ip));
        break;
      case RTA_GATEWAY:
        has_gw = 1;
        memcpy(&gw_ip, RTA_DATA(rt_attr), sizeof(dst_ip));
        break;
      }
      rt_attr = RTA_NEXT(rt_attr, nd_len);
    }
  }
  if(has_gw) {
    fprintf(stderr, "gw=<%s>\n", inet_ntoa(gw_ip));
  } else if(has_dst) {
    fprintf(stderr, "ip=<%s>\n", inet_ntoa(dst_ip));
  }


  /* Build GET NEIGHBOUR request */  
  request->nlmsg_type = RTM_GETNEIGH;
  request->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
  request->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  struct ndmsg *nd = NLMSG_DATA(request);
  nd->ndm_family = AF_INET;

  nl_len = rtnl_talk(request, &answer);;

  /* Parse GET NEIGHBOUR answer -> gw mac addr + interface num */
  int found = 0;
  while(!found && NLMSG_OK(answer, nl_len)) {
    //    struct in_addr dst_ip;
      
    struct ndmsg *nd_msg = (struct ndmsg *)NLMSG_DATA(answer);
    struct rtattr *rt_attr = (struct rtattr *)RTM_RTA(nd_msg);
    int rt_len = RTM_PAYLOAD(answer);
    ifnum = nd_msg->ndm_ifindex;
    while(RTA_OK(rt_attr, rt_len)) {
      switch (rt_attr->rta_type) {
      case NDA_LLADDR:
        memcpy(&params->dst_mac, RTA_DATA(rt_attr), IFHWADDRLEN);
        break;
      case NDA_DST:
        if((has_gw && (*(in_addr_t*)RTA_DATA(rt_attr) == *(in_addr_t*)&gw_ip)) ||
           (has_dst && (*(in_addr_t*)RTA_DATA(rt_attr) == *(in_addr_t*)&dst_ip))) {
          found = 1;
        }
        break;
      }
      rt_attr = RTA_NEXT(rt_attr, rt_len);
    }
    answer = NLMSG_NEXT(answer, nl_len);
  }
  if(found) {
    fprintf(stderr, "if=%d\ndst_mac=<%s>\n", ifnum, ether_ntoa(&params->dst_mac));
  }

  /* Get mac addr of interface ifnum */
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(fd == -1) {
    error("cannot open UDP socket. %s", strerror(errno));
  }
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_ifindex = ifnum;
  ioctl(fd, SIOCGIFNAME, &ifr);
  ioctl(fd, SIOCGIFHWADDR, &ifr);
  memcpy(&params->src_mac, ifr.ifr_hwaddr.sa_data, 6);
  fprintf(stderr, "src_mac=<%s>\n", ether_ntoa(&params->src_mac));
  close(fd);
}
