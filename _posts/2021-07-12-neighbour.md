---
title: "Linux Kernel Neighbour Subsystem"
categories: linux kernel
---

해당 포스트에서는 리눅스 커널의 이웃 탐색 시스템과 ARP 프로토콜 구현에 대해 설명합니다.  

## Neighbour Subsystem

이웃 서브시스템은 같은 링크 상의 노드가 존재하는지 탐색하고 L3 주소를 L2 주소로 변환한다.  
이러한 주소 변환을 구현한 프로토콜을 IPv4에서는 ARP라고 하고, IPv6에서는 NDISC라고 한다.  
이번 챕터에서는 IPv4와 IPv6의 이웃 탐색 서브시스템 공통 부분과 ARP를 설명한다.  
이웃 서브시스템 의뢰 요청과 의뢰 응답을 이용하면 L2 주소는 자신에게 부여된 L3 주소를 알아낼 수 있다.  

리눅스 이웃 서브시스템의 기본 자료구조는 neighbour 구조체다. 해당 구조체는 같은 L2 링크에 연결된 네트워크 노드를 나타낸다.  
```c
struct neighbour {
	struct neighbour __rcu	*next;
	struct neigh_table	*tbl;
	struct neigh_parms	*parms;
	unsigned long		confirmed;
	unsigned long		updated;
	rwlock_t		lock;
	refcount_t		refcnt;
	unsigned int		arp_queue_len_bytes;
	struct sk_buff_head	arp_queue;
	struct timer_list	timer;
	unsigned long		used;
	atomic_t		probes;
	__u8			flags;
	__u8			nud_state;
	__u8			type;
	__u8			dead;
	u8			protocol;
	seqlock_t		ha_lock;
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))] __aligned(8);
	struct hh_cache		hh;
	int			(*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops	*ops;
	struct list_head	gc_list;
	struct rcu_head		rcu;
	struct net_device	*dev;
	u8			primary_key[0];
} __randomize_layout;
```
* next : 해시 테이블에서 같은 bucket 상의 다음 이웃을 가리키는 포인터
* tbl : 객체의 이웃에 연관된 이웃 테이블
* parms : 해당 neighbour 객체에 연관된 파라미터 객체로, tbl 테이블의 constructor 함수를 통해 초기화된다.
* confirmed : 확인용 타임스탬프
* refcnt : 객체 참조 카운터. neigh_hold() 매크로로 증가하고, neigh_release() 함수로 감소하여 값이 0일 때 neight_destroy() 함수를 호출해 해제한다.
* arp_queue : unresolved SKB queue
* timer : 해당 객체의 타이머이다. 타이머 콜백은 neigh_timer_handler() 함수로, 네트워크 연결 불가 탐지(NUD) 상태를 변경할 수 있다.
* nud_state : 해당 객체(이웃)의 NUD 상태이다. [링크](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/neighbour.h#L53)의 값들이 동적으로 설정될 수 있다.
* dead : 이웃 객체의 해제 플래그로, neigh_destroy() 함수에서 dead 플래그가 설정된 객체만 해제한다.
* ha : 해당 객체의 하드웨어 주소로, 이더넷에서는 이웃의 MAC Address이다.
* hh : L2 헤더의 하드웨어 헤더 캐시
* output : 전송을 위한 콜백 함수를 가리키는 포인터이다. neigh_resolve_output() 함수나 neigh_direct_output() 함수가 설정될 수 있다. 이는 NUD 상태에 좌우되고 그 결과 이웃 생명주기 동안 다른 함수로 할당될 수 있다. 헬퍼 함수는 다음과 같다.
    * ```void neigh_connect(struct neighbour *neigh)``` : output 포인터를 neigh->ops->connected_output 함수로 설정한다.
    * ```void neigh_suspect(struct neighbour *neigh)``` : output 포인터를 neigh->ops->output 함수로 설정한다.
* primary_key : 이웃의 L3(IP) 주소이다. 이웃 테이블의 탐색은 primary_key로 수행한다.

각 neighbour 객체는 neigh_ops 구조체로 오퍼레이션을 정의한다. 구조체의 정의는 다음과 같다.  
```c
struct neigh_ops {
	int			family;
	void			(*solicit)(struct neighbour *, struct sk_buff *);
	void			(*error_report)(struct neighbour *, struct sk_buff *);
	int			(*output)(struct neighbour *, struct sk_buff *);
	int			(*connected_output)(struct neighbour *, struct sk_buff *);
};
```
* family : 프로토콜 계열(AF_INET, AF_INET6 등)
* solicit : 이웃 의뢰 요청을 담당하는 함수이며, arp_solicit() 함수나 ndisc_solicit() 함수가 할당된다.
* error_report : 이웃의 상태가 NUD_FAILED일 경우 [neigh_invalidate()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L999)에서 호출되는 함수이다. 예를 들어, 의뢰 요청이 응답되지 않으면 타임아웃이 만료된 후에 호출된다.
* output : 다음 홉의 L3 주소를 알고 있지만 L2 주소를 모르는 경우 neigh_resolve_output() 함수로 설정된다.
* connected_output : 이웃의 상태가 NUD_REACHABLE이나 NUD_CONNECTED일 경우 connected_output() 함수로 설정된다.

커널은 이웃 테이블 자료구조에 L3 주소와 L2 주소 간의 매핑을 유지한다.  
이웃 테이블 자료구조는 neigh_table 구조체로 표현되며, [arp 테이블](https://elixir.bootlin.com/linux/latest/source/net/ipv4/arp.c#L152)이나 [ndisc 테이블](https://elixir.bootlin.com/linux/latest/source/net/ipv6/ndisc.c#L109) 모두 neigh_table 구조체의 인스턴스이다.  
```c
struct neigh_table {
	int			family;
	unsigned int		entry_size;
	unsigned int		key_len;
	__be16			protocol;
	__u32			(*hash)(const void *pkey,
					const struct net_device *dev,
					__u32 *hash_rnd);
	bool			(*key_eq)(const struct neighbour *, const void *pkey);
	int			(*constructor)(struct neighbour *);
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	void			(*proxy_redo)(struct sk_buff *skb);
	int			(*is_multicast)(const void *pkey);
	bool			(*allow_add)(const struct net_device *dev,
					     struct netlink_ext_ack *extack);
	char			*id;
	struct neigh_parms	parms;
	struct list_head	parms_list;
	int			gc_interval;
	int			gc_thresh1;
	int			gc_thresh2;
	int			gc_thresh3;
	unsigned long		last_flush;
	struct delayed_work	gc_work;
	struct timer_list 	proxy_timer;
	struct sk_buff_head	proxy_queue;
	atomic_t		entries;
	atomic_t		gc_entries;
	struct list_head	gc_list;
	rwlock_t		lock;
	unsigned long		last_rand;
	struct neigh_statistics	__percpu *stats;
	struct neigh_hash_table __rcu *nht;
	struct pneigh_entry	**phash_buckets;
};
```
* entry_size : [neighbour 객체 할당](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L405)에 사용되는 이웃 엔트리 크기이다. [neigh_table_init()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L1711) 함수에서 neighbour 구조체의 primary_key 필드 오프셋 (즉, primary key를 제외한 객체 크기) + tbl->key_len을 sizeof(long long)에 정렬한 크기로 할당된다.
* key_len : 탐색 키의 크기이다. IPv4의 경우 주소의 길이가 4바이트 이므로 4바이트이다.
* hash : 키(L3 주소)를 지정한 해시 값과 매핑하는 해시 함수. arp_hash()나 ndisc_hash() 함수가 할당된다.
* constructor : neighbour 객체가 생성될 때 프로토콜에 특화된 초기화를 수행하는 콜백 함수이다. arp_constructor()나 ndisc_constructor() 함수가 할당된다. ___neigh_create() 함수에서 호출되며, 성공 시 0을 반환한다.
* pconstructor : neighbour proxy 생성을 위한 함수이다. pndisc_constructor이 할당된다.
* pdestructor : neighbour proxy 제거를 위한 함수이다. pndisc_destructor이 할당된다.
* id : 테이블의 이름이다. arp_cache나 ndisc_cache로 지정된다.
* parms : 테이블과 연관된 neigh_parms 객체로, 연결 가능성 정보나 타임아웃 등의 설정으로 구성된다.
* gc_thresh1, gc_thresh2, gc_thresh3 : 이웃 테이블 항목 수의 임계값으로, 동기 가비지 컬렉터(neigh_forced_gc)의 활성화 기준이나 비동기 가비지 컬렉터 핸들러(neigh_periodic_work())에서 사용된다. 해당 값은 ```/proc/sys/net/ipv[4|6]/neigh/default/gc_thresh[1-3]```에서 설정할 수 있다.
* last_flush : neigh_forced_gc() 함수가 시행된 가장 최근 시간이다.
* gc_work : 비동기 가비지 컬렉터 핸들러이다. [neigh_table_init()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L1718) 함수에서 neigh_periodic_work() 함수로 설정된다.
    * [neigh_periodic_work()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L891) : 테이블의 항목 수가 gc_thresh1 보다 적은지 검사하고, 그렇다면 바로 종료하며 아니라면 연결 가능 시간을 재계산한다. 그 후 이웃 해시 테이블을 살펴보고, 상태가 NUD_PERMANENT나 NUD_IN_TIMER거나 NTF_EXT_LEARNED 플래그가 설정된 항목은 해제 하지 않고 넘어간다. 그 외 항목에 대해 참조 카운터가 1이고 state가 NUD_FAILED이거나 현재 시간이 used 타임스탬프 + GC_STALETIME을 지난 항목에 대해 neigh_cleanup_and_release() 함수를 호출하여 제거한다.
* proxy_timer : 호스트가 ARP 프록시로 설정되는 경우 의뢰 요청을 일정 지연 시간을 두고 처리하기 위한 타이머이다. [neigh_table_init()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L1721) 함수에서 neigh_proxy_process() 콜백 함수가 등록된다.
* proxy_queue : 프록시 ARP의 SKB 큐
* stats : 통계를 위한 neigh_statistics 객체로, CPU 별로 할당된다.
* nht : 이웃 해시 테이블
* phash_buckets : 이웃 프록시 해시 테이블

arp_tbl 객체와 neigh_ops 객체들은 초기에 다음과 같이 정의되어 있다.
```c
static const struct neigh_ops arp_generic_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_connected_output,
};

static const struct neigh_ops arp_hh_ops = {
	.family =		AF_INET,
	.solicit =		arp_solicit,
	.error_report =		arp_error_report,
	.output =		neigh_resolve_output,
	.connected_output =	neigh_resolve_output,
};

static const struct neigh_ops arp_direct_ops = {
	.family =		AF_INET,
	.output =		neigh_direct_output,
	.connected_output =	neigh_direct_output,
};

struct neigh_table arp_tbl = {
	.family		= AF_INET,
	.key_len	= 4,
	.protocol	= cpu_to_be16(ETH_P_IP),
	.hash		= arp_hash,
	.key_eq		= arp_key_eq,
	.constructor	= arp_constructor,
	.proxy_redo	= parp_redo,
	.is_multicast	= arp_is_multicast,
	.id		= "arp_cache",
	.parms		= {
		.tbl			= &arp_tbl,
		.reachable_time		= 30 * HZ,
		.data	= {
			[NEIGH_VAR_MCAST_PROBES] = 3,
			[NEIGH_VAR_UCAST_PROBES] = 3,
			[NEIGH_VAR_RETRANS_TIME] = 1 * HZ,
			[NEIGH_VAR_BASE_REACHABLE_TIME] = 30 * HZ,
			[NEIGH_VAR_DELAY_PROBE_TIME] = 5 * HZ,
			[NEIGH_VAR_GC_STALETIME] = 60 * HZ,
			[NEIGH_VAR_QUEUE_LEN_BYTES] = SK_WMEM_MAX,
			[NEIGH_VAR_PROXY_QLEN] = 64,
			[NEIGH_VAR_ANYCAST_DELAY] = 1 * HZ,
			[NEIGH_VAR_PROXY_DELAY]	= (8 * HZ) / 10,
			[NEIGH_VAR_LOCKTIME] = 1 * HZ,
		},
	},
	.gc_interval	= 30 * HZ,
	.gc_thresh1	= 128,
	.gc_thresh2	= 512,
	.gc_thresh3	= 1024,
};
```

이러한 이웃 테이블에 추가적으로 필요한 작업은 arp_init() 함수에서 neigh_table_init() 함수를 호출하여 초기화한다.
```c
void __init arp_init(void)
{
	neigh_table_init(NEIGH_ARP_TABLE, &arp_tbl);

	dev_add_pack(&arp_packet_type);
	arp_proc_init();
#ifdef CONFIG_SYSCTL
	neigh_sysctl_register(NULL, &arp_tbl.parms, NULL);
#endif
	register_netdevice_notifier(&arp_netdev_notifier);
}

void neigh_table_init(int index, struct neigh_table *tbl)
{
	unsigned long now = jiffies;
	unsigned long phsize;

	INIT_LIST_HEAD(&tbl->parms_list);
	INIT_LIST_HEAD(&tbl->gc_list);
	list_add(&tbl->parms.list, &tbl->parms_list);
	write_pnet(&tbl->parms.net, &init_net);
	refcount_set(&tbl->parms.refcnt, 1);
	tbl->parms.reachable_time =
			  neigh_rand_reach_time(NEIGH_VAR(&tbl->parms, BASE_REACHABLE_TIME));

	tbl->stats = alloc_percpu(struct neigh_statistics);
	if (!tbl->stats)
		panic("cannot create neighbour cache statistics");

#ifdef CONFIG_PROC_FS
	if (!proc_create_seq_data(tbl->id, 0, init_net.proc_net_stat,
			      &neigh_stat_seq_ops, tbl))
		panic("cannot create neighbour proc dir entry");
#endif

	RCU_INIT_POINTER(tbl->nht, neigh_hash_alloc(3));

	phsize = (PNEIGH_HASHMASK + 1) * sizeof(struct pneigh_entry *);
	tbl->phash_buckets = kzalloc(phsize, GFP_KERNEL);

	if (!tbl->nht || !tbl->phash_buckets)
		panic("cannot allocate neighbour cache hashes");

	if (!tbl->entry_size)
		tbl->entry_size = ALIGN(offsetof(struct neighbour, primary_key) +
					tbl->key_len, NEIGH_PRIV_ALIGN);
	else
		WARN_ON(tbl->entry_size % NEIGH_PRIV_ALIGN);

	rwlock_init(&tbl->lock);
	INIT_DEFERRABLE_WORK(&tbl->gc_work, neigh_periodic_work);
	queue_delayed_work(system_power_efficient_wq, &tbl->gc_work,
			tbl->parms.reachable_time);
	timer_setup(&tbl->proxy_timer, neigh_proxy_process, 0);
	skb_queue_head_init_class(&tbl->proxy_queue,
			&neigh_table_proxy_queue_class);

	tbl->last_flush = now;
	tbl->last_rand	= now + tbl->parms.reachable_time * 20;

	neigh_tables[index] = tbl;
}
```

보다시피 인자로 전달받은 이웃 테이블의 항목들을 할당 및 초기화한다.  
ARP 프로토콜은 arp_init() 함수에서 dev_add_pack() 함수로 L3 프로토콜 핸들러를 등록한다.  
핸들러 객체인 arp_packet_type 객체는 다음과 같다.  
```c
static struct packet_type arp_packet_type __read_mostly = {
	.type =	cpu_to_be16(ETH_P_ARP),
	.func =	arp_rcv,
};
```

### 이웃 생성과 해제

이웃 객체는 ___neigh_create() 함수로 생성된다. 과거에 사용되던 [__neigh_create()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L674) 함수는 해당 함수의 래퍼이다.  
```c
static struct neighbour *___neigh_create(struct neigh_table *tbl,
					 const void *pkey,
					 struct net_device *dev,
					 bool exempt_from_gc, bool want_ref)
{
	struct neighbour *n1, *rc, *n = neigh_alloc(tbl, dev, exempt_from_gc);
	u32 hash_val;
	unsigned int key_len = tbl->key_len;
	int error;
	struct neigh_hash_table *nht;
	...
	/* Protocol specific setup. */
	if (tbl->constructor &&	(error = tbl->constructor(n)) < 0) {
		rc = ERR_PTR(error);
		goto out_neigh_release;
	}
	...
	n->confirmed = jiffies - (NEIGH_VAR(n->parms, BASE_REACHABLE_TIME) << 1);
	...
	if (atomic_read(&tbl->entries) > (1 << nht->hash_shift))
		nht = neigh_hash_grow(tbl, nht->hash_shift + 1);
	...
}

static struct neighbour *neigh_alloc(struct neigh_table *tbl,
				     struct net_device *dev,
				     bool exempt_from_gc)
{
	struct neighbour *n = NULL;
	unsigned long now = jiffies;
	int entries;

	if (exempt_from_gc)
		goto do_alloc;

	entries = atomic_inc_return(&tbl->gc_entries) - 1;
	if (entries >= tbl->gc_thresh3 ||
	    (entries >= tbl->gc_thresh2 &&
	     time_after(now, tbl->last_flush + 5 * HZ))) {
		if (!neigh_forced_gc(tbl) &&
		    entries >= tbl->gc_thresh3) {
			net_info_ratelimited("%s: neighbor table overflow!\n",
					     tbl->id);
			NEIGH_CACHE_STAT_INC(tbl, table_fulls);
			goto out_entries;
		}
	}

do_alloc:
	n = kzalloc(tbl->entry_size + dev->neigh_priv_len, GFP_ATOMIC);
	if (!n)
		goto out_entries;

	__skb_queue_head_init(&n->arp_queue);
	rwlock_init(&n->lock);
	seqlock_init(&n->ha_lock);
	n->updated	  = n->used = now;
	n->nud_state	  = NUD_NONE;
	n->output	  = neigh_blackhole;
	seqlock_init(&n->hh.hh_lock);
	n->parms	  = neigh_parms_clone(&tbl->parms);
	timer_setup(&n->timer, neigh_timer_handler, 0);

	NEIGH_CACHE_STAT_INC(tbl, allocs);
	n->tbl		  = tbl;
	refcount_set(&n->refcnt, 1);
	n->dead		  = 1;
	INIT_LIST_HEAD(&n->gc_list);

	atomic_inc(&tbl->entries);
out:
	return n;

out_entries:
	if (!exempt_from_gc)
		atomic_dec(&tbl->gc_entries);
	goto out;
}
```

우선 neigh_alloc() 함수를 호출하여 이웃 객체를 할당한다.  
neigh_alloc() 함수에서는 테이블 항목의 수가 gc_thresh3 보다 크거나 테이블 항목의 수가 gc_thresh2 보다 크고, 마지막으로 테이블을 비운 후 지나간 시간이 5Hz 보다 크면 동기화 가비지 컬렉터 함수(neigh_forced_gc())를 실행한다.  

___neigh_create() 함수는 이 후 등록된 [constructor 함수](https://elixir.bootlin.com/linux/latest/source/net/ipv4/arp.c#L222)를 호출하여 protocol specific setup, device spepcific setup 등을 진행한다.  

이웃 객체 생성 시 이웃 항목의 수가 해시 테이블 크기를 초과하면 해시 테이블을 확장해야 한다.  
해당 작업은 neigh_hash_grow() 함수를 호출하여 수행된다.  

이러한 작업의 결과들로 neighbour 객체가 이웃 해시 테이블에 추가된다.  

이웃 해제에는 neigh_release() 함수가 사용된다.  
```c
static inline void neigh_release(struct neighbour *neigh)
{
	if (refcount_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}
```
참조 카운트를 감소시키고, 카운트가 0이 되면 neigh_destroy 함수를 호출하여 해제한다.  
[neigh_destroy()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L834) 함수는 neighbour 객체의 dead 플래그가 설정되어 있는 경우에만 객체를 해제한다.  

### 유저 스페이스 상호작용

ARP 테이블은 iproute2 패키지의 ip neigh 명령과 net-tools 패키지의 arp 명령으로 관리할 수 있다.  
각 명령에 대한 ftrace 로그를 살펴보면 다음과 같다.  

* ```ip neigh show``` : neigh_dump_info() 함수로 처리된다.
```bash
              ip-2041    [000] ....   112.366694: neigh_dump_info <-netlink_dump
              ip-2041    [000] ....   112.366699: <stack trace>
 => neigh_dump_info
 => netlink_dump
 => __netlink_dump_start
 => rtnetlink_rcv_msg
 => netlink_rcv_skb
 => rtnetlink_rcv
 => netlink_unicast
 => netlink_sendmsg
 => sock_sendmsg
 => __sys_sendto
 => __x64_sys_sendto
 => do_syscall_64
 => entry_SYSCALL_64_after_hwframe
```

* ```arp -a``` : arp_seq_show() 함수로 처리된다.
```bash
             arp-2042    [002] ....   114.132257: arp_seq_show <-seq_read
             arp-2042    [002] ....   114.132261: <stack trace>
 => arp_seq_show
 => seq_read
 => proc_reg_read
 => vfs_read
 => ksys_read
 => __x64_sys_read
 => do_syscall_64
 => entry_SYSCALL_64_after_hwframe
```

## ARP Protocol 

패킷 전송 시 목적지 IPv4 주소를 알고 있을 것이다. 이 때 목적지 MAC 주소를 포함한 이더넷 헤더를 만들어야 한다.  
목적지 MAC 주소를 알지 못하는 경우, ARP 요청을 브로드캐스트로 전송한다. 이 ARP 요청에는 찾고 있는 IPv4 주소가 포함되어 있다.  
그러한 IPv4 주소를 가진 호스트가 있으면 응답으로 유니캐스트 ARP를 보낸다.  
ARP 헤더의 구조는 다음과 같다.  
![arp_header](https://github.com/pr0gr4m/pr0gr4m.github.io/blob/master/img/arp_header.png?raw=true)

커널에서 구현한 ARP 헤더의 구조체는 다음과 같다.   
```c
struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

#if 0
	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
#endif

};
```
* ar_hrd : 하드웨어 유형이며, 이더넷의 경우 0x01이다. [링크](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_arp.h#L29)에서 할당 가능한 목록들을 볼 수 있다.
* ar_pro : 프로토콜 ID이며, IPv4의 경우 0x80이다. [링크](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h#L47)에서 할당 가능한 목록들을 볼 수 있다.
* ar_hln : 바이트 단위의 하드웨어 주소 길이이며, 이더넷의 경우 6 바이트이다.
* ar_pln : 바이트 단위의 프로토콜 주소 길이이며, IPv4의 경우 4 바이트이다.
* ar_op : 동작코드(opcode)이며, ARP 요청의 경우 [ARPOP_REQUEST](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_arp.h#L106)이고, ARP 응답의 경우 [ARPOP_REPLY](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_arp.h#L107)이다.

ARP 헤더에서 opcode 이후에 송신자 하드웨어 주소, 네트워크 주소, 수신자 하드웨어 주소, 네트워크 주소가 온다.  
이는 arphdr 구조체 내에 포함되지 않고 arp_process() 함수에서 해당하는 오프셋을 읽어 추출한다.  

Neighbour Subsystem 챕터 초반에 본 바와 같이 ARP에는 [arp_generic_ops](https://elixir.bootlin.com/linux/latest/source/net/ipv4/arp.c#L130), [arp_hh_ops](https://elixir.bootlin.com/linux/latest/source/net/ipv4/arp.c#L138), [arp_direct_ops](https://elixir.bootlin.com/linux/latest/source/net/ipv4/arp.c#L146) 3개의 neigh_ops 객체가 정의돼 있다. (arp_broken_ops는 제거되었다.)  
ARP 테이블의 neigh_ops 객체는 네트워크 장치 기능을 토대로 arp_constructor() 함수를 통해 초기화된다.  
* net_device 객체의 header_ops가 NULL이면 neigh_ops 객체는 arp_direct_ops로 설정된다. 이 경우 패킷 전송은 neigh_direct_output() 함수에서 수행된다.
* net_device 객체의 header_ops에 cache 콜백이 NULL이면 neigh_ops 객체는 arp_generic_ops로 설정된다.
* net_device 객체의 header_ops에 cache 콜백이 NULL이 아니면 neigh_ops 객체는 arp_hh_ops로 설정될 것이다.

### ARP 의뢰 요청 전송

ARP 의뢰 요청은 arp_solicit() 함수로 수행한다.  
해당 함수가 어떤 상황에서 호출되는지 알아보기 위하여 dump_stack() 함수로 콜스택을 트레이싱 하면 다음과 같다.
```bash
[    4.803576] Call Trace:
[    4.803582]  dump_stack+0x74/0x9a
[    4.803585]  arp_solicit+0x47/0x22e
[    4.803587]  ? __skb_clone+0x2e/0x120
[    4.803588]  neigh_probe+0x52/0x70
[    4.803589]  __neigh_event_send+0xa8/0x330
[    4.803590]  neigh_resolve_output+0x128/0x1c0
[    4.803592]  ip_finish_output2+0x19b/0x590
[    4.803593]  __ip_finish_output+0xd3/0x210
[    4.803594]  ip_finish_output+0x2d/0xb0
[    4.803594]  ip_output+0x7a/0xf0
[    4.803595]  ? __ip_finish_output+0x210/0x210
[    4.803596]  ip_local_out+0x3d/0x50
[    4.803597]  ip_send_skb+0x19/0x40
[    4.803598]  udp_send_skb.isra.0+0x165/0x390
[    4.803599]  udp_sendmsg+0xb0e/0xd50
[    4.803600]  ? ip_reply_glue_bits+0x50/0x50
[    4.803602]  ? __mod_memcg_lruvec_state+0x25/0xe0
[    4.803604]  ? _cond_resched+0x19/0x30
[    4.803605]  ? aa_sk_perm+0x43/0x1b0
[    4.803606]  inet_sendmsg+0x65/0x70
[    4.803608]  ? security_socket_sendmsg+0x35/0x50
[    4.803609]  ? inet_sendmsg+0x65/0x70
[    4.803610]  sock_sendmsg+0x5e/0x70
[    4.803611]  sock_write_iter+0x93/0xf0
[    4.803613]  new_sync_write+0x18e/0x1a0
[    4.803614]  vfs_write+0x1a6/0x200
[    4.803615]  ksys_write+0xb1/0xe0
[    4.803617]  ? syscall_trace_enter.isra.0+0x8b/0x1d0
[    4.803618]  __x64_sys_write+0x1a/0x20
[    4.803618]  do_syscall_64+0x38/0x90
[    4.803620]  entry_SYSCALL_64_after_hwframe+0x44/0xa9

[   72.272896] Call Trace:
[   72.272898]  <IRQ>
[   72.272903]  dump_stack+0x74/0x9a
[   72.272907]  arp_solicit+0x47/0x22e
[   72.272909]  ? mod_timer+0x1aa/0x300
[   72.272911]  neigh_probe+0x52/0x70
[   72.272912]  neigh_timer_handler+0x92/0x310
[   72.272913]  ? neigh_update+0x20/0x20
[   72.272914]  call_timer_fn+0x32/0x130
[   72.272915]  __run_timers.part.0+0x1e6/0x270
[   72.272916]  ? ktime_get+0x3e/0xa0
[   72.272918]  ? native_apic_msr_write+0x2b/0x30
[   72.272920]  ? lapic_next_event+0x21/0x30
[   72.272922]  ? clockevents_program_event+0x8f/0xe0
[   72.272923]  run_timer_softirq+0x2a/0x50
[   72.272925]  __do_softirq+0xe1/0x2da

[   76.556415] Call Trace:
[   76.556420]  dump_stack+0x74/0x9a
[   76.556422]  arp_solicit+0x47/0x22e
[   76.556424]  ? __skb_clone+0x2e/0x120
[   76.556426]  neigh_probe+0x52/0x70
[   76.556427]  __neigh_event_send+0xa8/0x330
[   76.556427]  neigh_resolve_output+0x128/0x1c0
[   76.556429]  ip_finish_output2+0x19b/0x590
[   76.556430]  ? __ip_append_data.isra.0+0x91b/0xdf0
[   76.556431]  __ip_finish_output+0xd3/0x210
[   76.556432]  ? ping_close+0x70/0x70
[   76.556432]  ip_finish_output+0x2d/0xb0
[   76.556433]  ip_output+0x7a/0xf0
[   76.556434]  ? __ip_finish_output+0x210/0x210
[   76.556435]  ip_local_out+0x3d/0x50
[   76.556436]  ip_send_skb+0x19/0x40
[   76.556436]  ip_push_pending_frames+0x33/0x40
[   76.556437]  ping_v4_sendmsg+0x431/0x750
[   76.556440]  ? check_preempt_wakeup+0xfd/0x210
[   76.556442]  ? _raw_spin_unlock_bh+0x1e/0x20
[   76.556443]  inet_sendmsg+0x6c/0x70
[   76.556443]  ? inet_sendmsg+0x6c/0x70
[   76.556444]  sock_sendmsg+0x5e/0x70
[   76.556445]  __sys_sendto+0x113/0x190
[   76.556447]  ? exit_to_user_mode_prepare+0x3d/0x1b0
[   76.556448]  ? do_user_addr_fault+0x1ef/0x3b5
[   76.556449]  __x64_sys_sendto+0x29/0x30
[   76.556450]  do_syscall_64+0x38/0x90
```

의뢰 요청이 발생하는 경우는 크게 타이머 만료로 인한 주기적 의뢰 요청과, tx 경로에서 ip_finish_output2() 함수에서의 의뢰 요청이 있다.  
ip_finish_output() 함수에서는 다음과 같이 ip_neigh_for_gw() 함수를 호출하여 이웃 객체를 찾고, 해당 이웃 객체로 neigh_output() 함수를 호출하여 이웃 객체에 등록된 output() 콜백 함수를 호출한다.  
```c
static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);
	struct neighbour *neigh;
	...
	neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
	if (!IS_ERR(neigh)) {
		int res;

		sock_confirm_neigh(skb, neigh);
		/* if crossing protocols, can not use the cached header */
		res = neigh_output(neigh, skb, is_v6gw);
		rcu_read_unlock_bh();
		return res;
	}
	...
}
```
ip_neigh_for_gw() 함수는 Address Family에 따라 (AF_INET/AF_INET6) ip_neigh_gw4() 함수나 ip_neigh_gw6() 함수를 호출하도록 래핑되어 있다.  
ip_neigh_gw4() 함수의 정의는 다음과 같다.  
```c
static inline struct neighbour *ip_neigh_gw4(struct net_device *dev,
					     __be32 daddr)
{
	struct neighbour *neigh;

	neigh = __ipv4_neigh_lookup_noref(dev, daddr);
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &daddr, dev, false);

	return neigh;
}
```
__ipv4_neigh_lookup_noref() 함수를 호출하여 ARP 테이블에서 다음 홉 IPv4 주소 탐색을 수행하고, 일치하는 이웃 항목을 찾지 못할 경우 __neigh_create() 함수를 호출해 이웃 객체를 생성한다.  

ip_finish_output2() 함수에서 이웃 객체를 찾은 후 호출하는 neigh_output() 함수의 정의는 다음과 같다.  
```c
static inline int neigh_output(struct neighbour *n, struct sk_buff *skb,
			       bool skip_cache)
{
	const struct hh_cache *hh = &n->hh;

	if ((n->nud_state & NUD_CONNECTED) && hh->hh_len && !skip_cache)
		return neigh_hh_output(hh, skb);
	else
		return n->output(n, skb);
}
```

해당 함수에 처음 도달했을 경우, 이웃 객체의 nud_state는 NUD_CONNECTED가 아니며, 출력 콜백은 neigh_resolve_output() 함수가 된다.  
[neigh_resolve_output()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L1476) 함수에서는 [neigh_event_send()](https://elixir.bootlin.com/linux/latest/source/include/net/neighbour.h#L437) 함수를 호출하는데, 해당 함수 nud_state가 NUD_CONNECTED | NUD_DELAY | NUD_PROBE 중 하나라도 세팅되어 있다면 반환하여 neigh_resolve_output() 함수에서 ```rc = dev_queue_xmit(skb);``` 라인을 수행하게 된다. 이 경우 나중에 타이머 핸들러가 호출될 때 neigh_probe() 함수가 호출되어 해당 의뢰 요청을 처리할 것이다.  
하지만 처음 도달했을 경우, nud_state가 NUD_CONNECTED | NUD_DELAY | NUD_PROBE 가 아니므로, [__neigh_event_send()](https://elixir.bootlin.com/linux/latest/source/net/core/neighbour.c#L1111) 함수를 호출하게 되는데, 해당 함수에서 neigh_probe() 함수를 호출한다.  
```c
static void neigh_probe(struct neighbour *neigh)
	__releases(neigh->lock)
{
	struct sk_buff *skb = skb_peek_tail(&neigh->arp_queue);
	/* keep skb alive even if arp_queue overflows */
	if (skb)
		skb = skb_clone(skb, GFP_ATOMIC);
	write_unlock(&neigh->lock);
	if (neigh->ops->solicit)
		neigh->ops->solicit(neigh, skb);
	atomic_inc(&neigh->probes);
	consume_skb(skb);
}
```
neigh_probe() 함수는 위와 같이 solicit에 등록된 arp_solicit() 함수를 호출하여 ARP 의뢰 요청 패킷을 전송한다.  

arp_solicit() 함수의 정의는 다음과 같다.   
```c
static void arp_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	__be32 saddr = 0;
	u8 dst_ha[MAX_ADDR_LEN], *dst_hw = NULL;
	struct net_device *dev = neigh->dev;
	__be32 target = *(__be32 *)neigh->primary_key;
	int probes = atomic_read(&neigh->probes);
	struct in_device *in_dev;
	struct dst_entry *dst = NULL;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return;
	}
	switch (IN_DEV_ARP_ANNOUNCE(in_dev)) {
	default:
	case 0:		/* By default announce any local IP */
		if (skb && inet_addr_type_dev_table(dev_net(dev), dev,
					  ip_hdr(skb)->saddr) == RTN_LOCAL)
			saddr = ip_hdr(skb)->saddr;
		break;
	case 1:		/* Restrict announcements of saddr in same subnet */
		if (!skb)
			break;
		saddr = ip_hdr(skb)->saddr;
		if (inet_addr_type_dev_table(dev_net(dev), dev,
					     saddr) == RTN_LOCAL) {
			/* saddr should be known to target */
			if (inet_addr_onlink(in_dev, target, saddr))
				break;
		}
		saddr = 0;
		break;
	case 2:		/* Avoid secondary IPs, get a primary/preferred one */
		break;
	}
	rcu_read_unlock();

	if (!saddr)
		saddr = inet_select_addr(dev, target, RT_SCOPE_LINK);

	probes -= NEIGH_VAR(neigh->parms, UCAST_PROBES);
	if (probes < 0) {
		if (!(neigh->nud_state & NUD_VALID))
			pr_debug("trying to ucast probe in NUD_INVALID\n");
		neigh_ha_snapshot(dst_ha, neigh, dev);
		dst_hw = dst_ha;
	} else {
		probes -= NEIGH_VAR(neigh->parms, APP_PROBES);
		if (probes < 0) {
			neigh_app_ns(neigh);
			return;
		}
	}

	if (skb && !(dev->priv_flags & IFF_XMIT_DST_RELEASE))
		dst = skb_dst(skb);
	arp_send_dst(ARPOP_REQUEST, ETH_P_ARP, target, dev, saddr,
		     dst_hw, dev->dev_addr, NULL, dst);
}
```

IN_DEV_ARP_ANNOUNCE() 매크로는 ```/proc/sys/net/ipv4/conf/<netDevice>/arp_announce```와 ```/proc/sys/net/ipv4/conf/all/arp_announce```의 최대 값을 반환하며, 값에 따른 동작은 다음과 같다.  
* 0 : 기본 값으로, 모든 로컬 IP에 알림
* 1 : 같은 서브넷 상의 saddr로 알림을 제한
* 2 : 보조 IP를 사용하지 않고 기본/선호 IP를 구함

inet_select_addr() 함수에서는 지정된 범위보다 범위가 작고 대상과 서브넷이 같은 장치의 첫 번째 기본 인터페이스의 주소를 반환한다.  

유저 스페이스 ARP 데몬이 동작할 경우 neigh_app_ns() 함수가 동작하고 반환한다.
그렇지 않다면 (일반적인 경우) 최종적으로 arp_send_dst() 함수로 실제 arp 패킷 전송이 시작된다.  
```c
/* Create and send an arp packet. */
static void arp_send_dst(int type, int ptype, __be32 dest_ip,
			 struct net_device *dev, __be32 src_ip,
			 const unsigned char *dest_hw,
			 const unsigned char *src_hw,
			 const unsigned char *target_hw,
			 struct dst_entry *dst)
{
	struct sk_buff *skb;

	/* arp on this interface. */
	if (dev->flags & IFF_NOARP)
		return;

	skb = arp_create(type, ptype, dest_ip, dev, src_ip,
			 dest_hw, src_hw, target_hw);
	if (!skb)
		return;

	skb_dst_set(skb, dst_clone(dst));
	arp_xmit(skb);
}
```

ARP 비활성화 여부를 검사한 후, arp_create() 함수로 SKB를 생성한다.  
이 후 skb_dst_set() 함수로 SKB의 dst를 설정하고, [arp_xmit()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/arp.c#L638) 함수를 호출하여 패킷을 전송한다.  

### ARP 의뢰 요청 수신 및 응답

ARP 패킷 수신 핸들러인 arp_rcv() 함수의 정의는 다음과 같다.   
```c
static int arp_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	const struct arphdr *arp;

	/* do not tweak dropwatch on an ARP we will ignore */
	if (dev->flags & IFF_NOARP ||
	    skb->pkt_type == PACKET_OTHERHOST ||
	    skb->pkt_type == PACKET_LOOPBACK)
		goto consumeskb;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto out_of_mem;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */
	if (!pskb_may_pull(skb, arp_hdr_len(dev)))
		goto freeskb;

	arp = arp_hdr(skb);
	if (arp->ar_hln != dev->addr_len || arp->ar_pln != 4)
		goto freeskb;

	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));

	return NF_HOOK(NFPROTO_ARP, NF_ARP_IN,
		       dev_net(dev), NULL, skb, dev, NULL,
		       arp_process);

consumeskb:
	consume_skb(skb);
	return NET_RX_SUCCESS;
freeskb:
	kfree_skb(skb);
out_of_mem:
	return NET_RX_DROP;
}
```

