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