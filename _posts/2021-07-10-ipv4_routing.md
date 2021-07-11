---
title: "Linux Kernel IPv4 Routing Subsystem"
categories: linux kernel
---

해당 포스트에서는 리눅스 커널의 IPv4 라우팅 서브시스템 구현에 대해 설명합니다.

## Forwarding & FIB

FIB는 Forwarding Information Base의 약어로 Forwarding Table 혹은 MAC Table이라고도 한다.  
라우팅 작업 등에서 FIB 정보를 이용하여 입력 인터페이스가 패킷을 전달해야하는 적절한 출력 인터페이스를 찾는다.  
라우터는 라우팅 테이블이라고 하는 자료구조에 따라 수신 패킷을 포워딩 하는데, 이를 라우팅이라고 한다.  
라우팅 과정에서 수신 패킷은 라우터 장비의 커널 네트워킹 스택의 2계층에서 3계층으로 이동한다. (4계층으로는 이동할 필요가 없기 때문에 이동하지 않는다.)
해당 트래픽은 3계층에서 처리되고, 포워딩 라우터 장비에 설정된 라우팅 테이블에 따라 패킷은 송신 인터페이스에 전달되거나 거부된다.  
라우팅 테이블에 default gateway를 정의하면 다른 라우팅 항목으로 처리할 수 없는 모든 패킷은 IP 헤더에 있는 목적지 주소와 상관 없이 default gateway로 포워딩된다.  
default route는 CIDR(Classless Inter-Domain Routing) 표기법으로 0.0.0.0/0으로 지정된다.  

## Routing Lookup

라우팅 서브시스템의 탐색(Lookup)은 패킷마다 수행되며, Rx/Tx 경로에서 모두 수행된다.  
커널 3.6 이 전 버전에서는 탐색 과정이 라우팅 캐시 탐색과 캐시 미스 시 라우팅 테이블 탐색 단계로 나뉘어졌다.  
하지만 라우팅 캐시는 DoS 공격에 취약하다는 문제점이 있어 제거되고, 라우팅 테이블을 TRIE 자료구조로 구현하여 직접 탐색하게 되었다.  
라우팅 테이블 탐색을 수행하는 fib_lookup() 함수의 정의는 다음과 같다.
```c
#ifndef CONFIG_IP_MULTIPLE_TABLES
#define TABLE_LOCAL_INDEX	(RT_TABLE_LOCAL & (FIB_TABLE_HASHSZ - 1))
#define TABLE_MAIN_INDEX	(RT_TABLE_MAIN  & (FIB_TABLE_HASHSZ - 1))

static inline struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct hlist_node *tb_hlist;
	struct hlist_head *ptr;

	ptr = id == RT_TABLE_LOCAL ?
		&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
		&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];

	tb_hlist = rcu_dereference_rtnl(hlist_first_rcu(ptr));

	return hlist_entry(tb_hlist, struct fib_table, tb_hlist);
}

static inline int fib_lookup(struct net *net, const struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
{
	struct fib_table *tb;
	int err = -ENETUNREACH;

	rcu_read_lock();

	tb = fib_get_table(net, RT_TABLE_MAIN);
	if (tb)
		err = fib_table_lookup(tb, flp, res, flags | FIB_LOOKUP_NOREF);

	if (err == -EAGAIN)
		err = -ENETUNREACH;

	rcu_read_unlock();

	return err;
}
#else /* CONFIG_IP_MULTIPLE_TABLES */
int __fib_lookup(struct net *net, struct flowi4 *flp,
		 struct fib_result *res, unsigned int flags);

static inline int fib_lookup(struct net *net, struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
{
	struct fib_table *tb;
	int err = -ENETUNREACH;

	flags |= FIB_LOOKUP_NOREF;
	if (net->ipv4.fib_has_custom_rules)
		return __fib_lookup(net, flp, res, flags);

	rcu_read_lock();

	res->tclassid = 0;

	tb = rcu_dereference_rtnl(net->ipv4.fib_main);
	if (tb)
		err = fib_table_lookup(tb, flp, res, flags);

	if (!err)
		goto out;

	tb = rcu_dereference_rtnl(net->ipv4.fib_default);
	if (tb)
		err = fib_table_lookup(tb, flp, res, flags);

out:
	if (err == -EAGAIN)
		err = -ENETUNREACH;

	rcu_read_unlock();

	return err;
}
#endif /* CONFIG_IP_MULTIPLE_TABLES */
```

보다시피 주요 루틴은 fib_table_lookup()에서 수행하며, 해당 함수는 추후에 살펴본다.  
인자로 전달받는 [flowi4](https://elixir.bootlin.com/linux/latest/source/include/net/flow.h#L69) 객체는 source address, destination address, type of service, protocol 등을 비롯하여 IPv4 라우팅 탐색에 필요한 필드로 구성되어 있다. 해당 객체는 fib_lookup() 함수를 호출하기 전에 초기화되어야 한다.  
마찬가지로 인자로 전달받는 [fib_result](https://elixir.bootlin.com/linux/latest/source/include/net/ip_fib.h#L165) 객체는 탐색 과정 중에 만들어진다. fib_result 구조체의 정의는 다음과 같다.
```c
struct fib_result {
	__be32			prefix;
	unsigned char		prefixlen;
	unsigned char		nh_sel;
	unsigned char		type;
	unsigned char		scope;
	u32			tclassid;
	struct fib_nh_common	*nhc;
	struct fib_info		*fi;
	struct fib_table	*table;
	struct hlist_head	*fa_head;
};
```
* prefix : 넷마스크 접두사.
* prefixlen : 넷마스크를 나타내는 접두사의 길이. 예를 들어, ```ip route add 192.168.2.0/24 dev eth0``` 로 라우팅 항목을 추가할 경우 지정된 넷마스크에 따라 prefixlen은 24가 된다. 값의 범위는 0 ~ 32이며, default route를 사용할 경우 0으로 설정된다.
* nh_sel : 다음 홉 개수. 하나의 다음 홉으로만 동작하면 해당 값은 0이다. Multipath Routing으로 동작하면 다음 홉이 여러 개일 수 있다.
* type : 패킷 처리 방식을 결정하는 필드이다. 해당 필드에 따라 패킷을 다른 장비로 포워딩할지, 로컬에 전달할지, 폐기할지 등이 결정된다. 가장 일반적으로 지정되는 두 가지는 RTN_UNICAST 형식(게이트웨이나 직접 경로를 통해 패킷을 포워딩할 때 설정)과 RTN_LOCAL 형식(로컬 호스트에 대한 패킷일때 설정)이 있다. 설정할 수 있는 값은 [링크](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/rtnetlink.h#L244)를 참고한다.
* fi : fib_info 라우팅 항목을 나타내는 포인터이다. fib_info 객체는 다음 홉에 대한 참조를 담고 있으며, 추후에 설명한다.
* table : 탐색이 수행되는 FIB 테이블을 가리키는 포인터이다.
* fa_head : fib_alias 리스를 가리키는 포인터이다. fib_alias 객체를 사용할 경우 각 라우팅 항목마다 별도의 fib_info 객체가 생성되는 것을 방지함으로써 라우팅 항목의 최적화가 이뤄진다. fib_alias 구조체는 추후에 설명한다.

fib_lookup() 함수는 fib_get_table() 함수로 Main 혹은 Local FIB 테이블을 가져와 fib_table_lookup() 함수로 탐색을 수행한다.  
탐색이 성공적으로 수행되고 나면 [dst 객체](https://elixir.bootlin.com/linux/latest/source/include/net/dst.h#L25)가 생성되며, 주요 필드는 이 전 IPv4 포스트에서 언급했듯이 input과 output 콜백이다. 해당 콜백은 라우팅 탐색 결과에 따라 적절한 핸들러가 할당된다.  
dst 객체는 rtable 구조체에 포함되며, rtable 객체는 SKB와 연관된 라우팅 항목을 나타낸다. rtable 구조체의 정의는 다음과 같다.  
```c
struct rtable {
	struct dst_entry	dst;

	int			rt_genid;
	unsigned int		rt_flags;
	__u16			rt_type;
	__u8			rt_is_input;
	__u8			rt_uses_gateway;

	int			rt_iif;

	u8			rt_gw_family;
	/* Info on neighbour */
	union {
		__be32		rt_gw4;
		struct in6_addr	rt_gw6;
	};

	/* Miscellaneous cached information */
	u32			rt_mtu_locked:1,
				rt_pmtu:31;

	struct list_head	rt_uncached;
	struct uncached_list	*rt_uncached_list;
};
```
* rt_flags : rtable 객체의 플래그 값으로, 주요 값은 다음과 같다.
    * RTCF_BROADCAST : 해당 플래그가 설정되면 목적지 주소가 브로드캐스트 주소에 해당한다.
    * RTCF_MULTICAST : 해당 플래그가 설정되면 목적지 주소가 멀티캐스트 주소에 해당한다.
    * RTCF_DOREDIRECT : 해당 플래그가 설정되면 ICMPv4 Redirect 메시지가 수신 패킷의 응답으로 전송된다.
    * RTCF_LOCAL : 해당 플래그가 설정되면 목적지 주소가 로컬에 해당한다.
    * 그 외에도 여러 플래그가 있으며, [링크](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/in_route.h#L13)에서 확인할 수 있다. 일부 플래그는 동시에 사용할 수 있으며, 일부 플래그는 더 이상 사용하지 않는다. (사용하지 않는 플래그는 주석에 unused로 표기된다.)
* rt_is_input : 입력 경로에서 1로 설정되는 플래그이다.
* rt_uses_gateway : 다읍 홉이 gateway이면 1이며, 다음 홉이 직접 경로이면 0이다.
* rt_iif : 수신 인터페이스의 ifindex이다.
* rt_pmtu : 경로 상의 가장 작은 MTU

## FIB Table

라우팅 테이블은 fib_table 구조체로 표현된다. 해당 구조체의 정의는 다음과 같다.  
```c
struct fib_table {
	struct hlist_node	tb_hlist;
	u32			tb_id;
	int			tb_num_default;
	struct rcu_head		rcu;
	unsigned long 		*tb_data;
	unsigned long		__data[];
};
```
* tb_id : 테이블 식별자. Policy Routing을 사용하지 않으면 [rt_class_t](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/rtnetlink.h#L338)에 정의되어 있는 기본 테이블만 생성 및 식별된다. (RT_TABLE_MAIN, RT_TABLE_LOCAL)
* tb_num_default : 테이블 기본 경로 개수. 테이블을 생성하는 fib_trie_table() 함수에서 0으로 초기화된다. 기본 경로가 추가되면 fib_table_insert() 함수를 통해 1 증가하고, 기본 경로가 삭제되면 fib_table_delete() 함수를 통해 1 감소한다.

### fib_info

각 라우팅 항목들은 fib_info 구조체로 표현된다. fib_info 객체는 [fib_create_info()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_semantics.c#L1347) 함수로 생성되며, [fib_info_hash](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_semantics.c#L51)라고 하는 해시 테이블에 저장된다.  
[fib_info_cnt](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_semantics.c#L54)라고 하는 fib_info 객체의 전역 카운터가 있는데, 해당 카운터는 fib_create_info() 함수에서 fib_info 객체를 생성하면 증가하고, [free_fib_info()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_semantics.c#L248) 함수에서 fib_info 객체가 해제되면 감소한다.  
fib_info_hash 해시 테이블은 해당 카운터에 따라 크기가 동적으로 조정된다. 또한, 테이블의 탐색은 [fib_find_info()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_semantics.c#L399) 함수에 의해 이뤄진다.  
fib_info 구조체의 정의는 다음과 같다.  
```c
struct fib_info {
	struct hlist_node	fib_hash;
	struct hlist_node	fib_lhash;
	struct list_head	nh_list;
	struct net		*fib_net;
	int			fib_treeref;
	refcount_t		fib_clntref;
	unsigned int		fib_flags;
	unsigned char		fib_dead;
	unsigned char		fib_protocol;
	unsigned char		fib_scope;
	unsigned char		fib_type;
	__be32			fib_prefsrc;
	u32			fib_tb_id;
	u32			fib_priority;
	struct dst_metrics	*fib_metrics;
#define fib_mtu fib_metrics->metrics[RTAX_MTU-1]
#define fib_window fib_metrics->metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics->metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics->metrics[RTAX_ADVMSS-1]
	int			fib_nhs;
	bool			fib_nh_is_v6;
	bool			nh_updated;
	struct nexthop		*nh;
	struct rcu_head		rcu;
	struct fib_nh		fib_nh[];
};
```
주요 필드를 설명하면 다음과 같다.
* fib_treeref : fib_alias 객체의 수를 나타내는 카운터이다. fib_alias 객체는 fib_info 객체에 대한 참조를 가지고 있다.
* fib_clntref : fib_info 객체에 대한 참조 카운터이다. 해당 필드가 0이 되면 fib_info 객체가 할당 해제된다.
* fib_dead : fib_info 객체의 해제가 허용됐는지를 가리키는 플래그.
* fib_protocol : 해당 경로의 라우팅 프로토콜 식별자이다. 예를 들어 ```ip route add proto static 192.168.5.3 via 192.168.2.1```와 같이 추가할 수 있다. 다음과 같은 값을 가질 수 있다.
    * RTPROT_UNSPEC : 오류 값
    * RTPROT_REDIRECT : 해당 라우터 항목이 수신 ICMP 재지정 메시지의 결과로 생성된 것이다.
    * RTPROT_KERNEL : 라우팅 항목이 커널에서 생성된 것이다.
    * RTPROT_BOOT : 해당 플래그가 설정되면 관리자가 proto static 한정자를 지정하지 않고 경로를 추가한 것이다.
    * RTPROT_STATIC : 시스템 관리자가 설치한 경로이다.
    * 그 외에도 사용자 라우팅 데몬에 의해 항목이 추가되면 다양한 값이 설정될 수 있다.
* fib_scope : 목적지 주소의 범위이다. 범위는 다른 노드에서 호스트까지의 거리를 가리킨다. 다음 중 하나가 될 수 있다.
    * RT_SCOPE_HOST : 노드는 다른 네트워크 노드와 통신할 수 없다. 루프백 주소의 범위이다.
        * 로컬 경로인 경우 해당 값이 할당된다.
    * RT_SCOPE_UNIVERSE : 어디서든 사용될 수 있는 주소의 범위이다.
        * 모든 게이트웨이 유니캐스트 경로에는 해당 값이 할당된다.
    * RT_SCOPE_LINK : 해당 주소는 직접 연결된 호스트에서만 접근할 수 있다.
        * 직접 유니캐스트와 브로드캐스트 경로인 경우 해당 값이 할당된다.
    * RT_SCOPE_SITE : IPv6에서 사용되는 범위
    * RT_SCOPE_NOWHERE : 존재하지 않는 목적지 범위
* fib_type : 경로의 형식이다. 예를 들어 ```ip route add prohibit 192.168.1.17 from 192.168.2.103``` 같이 추가하면 RTN_PROHIBIT으로 설정된다.
* fib_priority : 경로의 우선순위이다. 기본 값이 0이며, 값이 낮을수록 우선순위가 높아진다.
* fib_nhs : 다음 홉의 개수이다. 다중경로 라우팅이 설정돼 있지 않으면 이 값은 1보다 클 수 없다.
* fib_dev : 다음 홉으로 패킷을 전송할 네트워크 장치
* fib_nh : 다음 홉을 나타내며, 단일경로 라우팅에서는 fib_nh[0]만 사용된다.

모든 경로 타입에 따른 error와 scope가 fib_props라는 전역 변수에 저장되어 있다. 해당 배열은 다음과 같다.
```c
const struct fib_prop fib_props[RTN_MAX + 1] = {
	[RTN_UNSPEC] = {
		.error	= 0,
		.scope	= RT_SCOPE_NOWHERE,
	},
	[RTN_UNICAST] = {
		.error	= 0,
		.scope	= RT_SCOPE_UNIVERSE,
	},
	[RTN_LOCAL] = {
		.error	= 0,
		.scope	= RT_SCOPE_HOST,
	},
	[RTN_BROADCAST] = {
		.error	= 0,
		.scope	= RT_SCOPE_LINK,
	},
	[RTN_ANYCAST] = {
		.error	= 0,
		.scope	= RT_SCOPE_LINK,
	},
	[RTN_MULTICAST] = {
		.error	= 0,
		.scope	= RT_SCOPE_UNIVERSE,
	},
	[RTN_BLACKHOLE] = {
		.error	= -EINVAL,
		.scope	= RT_SCOPE_UNIVERSE,
	},
	[RTN_UNREACHABLE] = {
		.error	= -EHOSTUNREACH,
		.scope	= RT_SCOPE_UNIVERSE,
	},
	[RTN_PROHIBIT] = {
		.error	= -EACCES,
		.scope	= RT_SCOPE_UNIVERSE,
	},
	[RTN_THROW] = {
		.error	= -EAGAIN,
		.scope	= RT_SCOPE_UNIVERSE,
	},
	[RTN_NAT] = {
		.error	= -EINVAL,
		.scope	= RT_SCOPE_NOWHERE,
	},
	[RTN_XRESOLVE] = {
		.error	= -EINVAL,
		.scope	= RT_SCOPE_NOWHERE,
	},
};
```

예를 들어 RTN_UNICAST 경로 type이면, 오류는 없고 경로 범위가 RT_SCOPE_UNIVERSE이다. RTN_PROHIBIT이면 오류 값은 -EACESS이고, 범위는 RT_SCOPE_UNIVERSE이다.  
위에서 언급한 fib_table_lookup() 함수에서 경로를 찾은 후, 경로의 type에 따라 error를 식별하여 다음과 같이 탐색을 중단할 수 있다.  
```c
		err = fib_props[fa->fa_type].error;
		if (unlikely(err < 0)) {
out_reject:
#ifdef CONFIG_IP_FIB_TRIE_STATS
			this_cpu_inc(stats->semantic_match_passed);
#endif
			trace_fib_table_lookup(tb->tb_id, flp, NULL, err);
			return err;
		}
```
위 경우 fib_lookup() 함수는 오류를 반환하고 오류 값에 따라 특정 동작이 일어난다.  
예를 들어, -EACCESS의 경우 ICMP_PKT_FILTERED 코드가 설정된 ICMPv4 메시지가 회신되고 패킷이 drop된다.  

### Next Hop

다음 홉을 나타내는 fib_nh 구조체의 정의는 다음과 같다.  
```c
struct fib_nh_common {
	struct net_device	*nhc_dev;
	int			nhc_oif;
	unsigned char		nhc_scope;
	u8			nhc_family;
	u8			nhc_gw_family;
	unsigned char		nhc_flags;
	struct lwtunnel_state	*nhc_lwtstate;

	union {
		__be32          ipv4;
		struct in6_addr ipv6;
	} nhc_gw;

	int			nhc_weight;
	atomic_t		nhc_upper_bound;

	/* v4 specific, but allows fib6_nh with v4 routes */
	struct rtable __rcu * __percpu *nhc_pcpu_rth_output;
	struct rtable __rcu     *nhc_rth_input;
	struct fnhe_hash_bucket	__rcu *nhc_exceptions;
};

struct fib_nh {
	struct fib_nh_common	nh_common;
	struct hlist_node	nh_hash;
	struct fib_info		*nh_parent;
#ifdef CONFIG_IP_ROUTE_CLASSID
	__u32			nh_tclassid;
#endif
	__be32			nh_saddr;
	int			nh_saddr_genid;
#define fib_nh_family		nh_common.nhc_family
#define fib_nh_dev		nh_common.nhc_dev
#define fib_nh_oif		nh_common.nhc_oif
#define fib_nh_flags		nh_common.nhc_flags
#define fib_nh_lws		nh_common.nhc_lwtstate
#define fib_nh_scope		nh_common.nhc_scope
#define fib_nh_gw_family	nh_common.nhc_gw_family
#define fib_nh_gw4		nh_common.nhc_gw.ipv4
#define fib_nh_gw6		nh_common.nhc_gw.ipv6
#define fib_nh_weight		nh_common.nhc_weight
#define fib_nh_upper_bound	nh_common.nhc_upper_bound
};
```
IPv6를 위한 fib6_nh 구조체가 생기면서 주요한 공동 부분은 fib_nh_common 구조체에 위치하게 되었다.  
주요 멤버는 다음과 같다.  
* nh_dev : 송신할 다음 홉 네트워크 장치이다.
* nh_oif : 송신할 다음 홉 인터페이스 index이다.
* nh_scope : 송신할 다음 홉 scope이다.
* nh_rth_input : Rx 경로의 fib_result 객체 캐시를 위한 필드이다.
* nh_pcpu_rth_output : Tx 경로의 fib_result 객체 캐시를 위한 필드이다.

nh_dev에 설정되어 있는 네트워크 장치가 비활성화되면 NETDEV_DOWN 알림이 전송된다.  
이 이벤트를 처리하는 함수는 [fib_netdev_event()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L1443)이다.  
해당 콜백은 [ip_fib_init()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L1618)함수에서 [fib_netdev_notifier](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L1506) 객체를 통해 등록한다.  
fib_netdev_event() 함수는 NETDEV_DOWN 이벤트를 수신하면 [fib_disable_ip()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L1402) 함수를 호출한다. 해당 함수의 정의는 다음과 같다.  
```c
static void fib_disable_ip(struct net_device *dev, unsigned long event,
			   bool force)
{
	if (fib_sync_down_dev(dev, event, force))	// fib_flags나 fib_nh_flags에 RTNH_F_DEAD 플래그를 설정한다.
		fib_flush(dev_net(dev));		// 경로가 비워진다.
	else
		rt_cache_flush(dev_net(dev));
	arp_ifdown(dev);
}
```

#### Next Hop Exception

라우팅 항목이 사용자(관리자)의 명령이 아닌 ICMPv4 재지정 메시지의 결과 등으로 변경되는 경우를 처리하기 위하여 다음 홉 예외를 사용한다.  
다음 홉 예외 처리를 위한 구조체 fib_nh_exception의 정의는 다음과 같다.  
```c
struct fib_nh_exception {
	struct fib_nh_exception __rcu	*fnhe_next;
	int				fnhe_genid;
	__be32				fnhe_daddr;
	u32				fnhe_pmtu;
	bool				fnhe_mtu_locked;
	__be32				fnhe_gw;
	unsigned long			fnhe_expires;
	struct rtable __rcu		*fnhe_rth_input;
	struct rtable __rcu		*fnhe_rth_output;
	unsigned long			fnhe_stamp;
	struct rcu_head			rcu;
};
```
다음 홉 예외는 [update_or_create_fnhe()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/route.c#L627)함수로 생성되는데, 해당 함수는 다음과 같은 상황에서 사용된다.
* [__ip_do_redirect()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/route.c#L777) 함수에서 ICMPv4 Redirect 메시지를 수신한 경우
* [__ip_rt_update_pmtu()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/route.c#L1029) 함수에서 PMTU(경로의 최소 MTU)가 변경된 경우

### Policy Routing

Routing Lookup에서 보았던 CONFIG_IP_MULTIPLE_TABLES 옵션이 설정되면 정책 라우팅을 사용한다.  

정책 라우팅을 사용하지 않으면 [fib4_rules_init()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L51) 함수에 의해 로컬 테이블과 메인 테이블만 생성된다.  
로컬 테이블은 로컬 주소의 라우팅 항목을 포함하며, 라우팅 항목은 커널에 의해 로컬 테이블에만 추가될 수 있다.  
메인 테이블은 시스템 관리자에 의해 ```ip route add``` 등의 명령으로 항목이 추가된다.  

정책 라우팅을 사용하면 다른 [fib4_rules_init()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_rules.c#L408) 함수에 의해 rule이 초기화된다.  
이 경우 초기 테이블로 Local, Main, Default 테이블이 생성되고, 255개의 라우팅 테이블이 만들어질 수 있다.  

메인 테이블에는 시스템 관리자 명령인 ip 또는 route를 통해 다음과 같이 접근할 수 있다.  
* ```ip route add``` : 경로 추가 시 사용자 공간에서 RTM_NEWROUTE 메시지를 전송하여 [inet_rtm_newroute()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L866) 함수에서 처리
* ```ip route del``` : 경로 삭제 시 사용자 공간에서 RTM_DELROUTE 메시지를 전송하여 [inet_rtm_delroute()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L836) 함수에서 처리
* ```ip route show``` : 메인 테이블 덤프 시 사용자 공간에서 RTM_GETROUTE 메시지를 전송하여 [inet_dump_finb()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_frontend.c#L965) 함수에서 처리
* ```route show table local``` : 로컬 테이블 덤프 명령어
* ```route add/del``` : IOCTL 메시지를 ip_rt_ioctl() 함수에서 처리

### FIB Alias

다음과 같이 목적지 주소나 서브넷이 같고 TOS만 다른 라우팅 항목이 여러 개 생성될 수 있다.
```bash
$ ip route add 192.168.1.10 via 192.168.2.1 tos 0x2
$ ip route add 192.168.1.10 via 192.168.2.1 tos 0x4
$ ip route add 192.168.1.10 via 192.168.2.1 tos 0x6
```

이러한 경우 각 경로마다 fib_info가 생성되는 대신 fib_alias 객체가 생성된다. fib_alias 구조체의 정의는 다음과 같다.  
```c
struct fib_alias {
	struct hlist_node	fa_list;
	struct fib_info		*fa_info;
	u8			fa_tos;
	u8			fa_type;
	u8			fa_state;
	u8			fa_slen;
	u32			tb_id;
	s16			fa_default;
	u8			offload:1,
				trap:1,
				offload_failed:1,
				unused:5;
	struct rcu_head		rcu;
};
```

fib_alias 객체는 서브넷은 같지만 매개변수가 다른 경로를 저장한다. 여러 개의 fib_alias 객체에서 하나의 fib_info 객체를 공유할 수 있다.  
이 경우 fib_alias 객체의 fa_info 멤버가 같은 fib_info 객체를 가리킬 것이다.  
다음 그림은 예시 명령어의 결과로 fa_tos만 다른 세 개의 fib_alias 객체가 하나의 fib_info를 공유하는 모습이다.
![fib_alias](https://github.com/pr0gr4m/pr0gr4m.github.io/blob/master/img/fib_alias.png?raw=true)

fib_alias 생성은 [fib_table_insert()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_trie.c#L1203) 함수에서 일어난다.  
TOS가 0x02인 fib_info가 생성된 상태에서 TOS가 0x04인 라우팅 항목을 생성한다고 가정하면 다음과 같다.  
1. ```fi = fib_create_info(cfg, extack);``` 라인에서 fib_info 객체 생성
2. [fib_create_info()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_semantics.c#L1347) 함수에서 ```fi = kzalloc(struct_size(fi, fib_nh, nhs), GFP_KERNEL);``` 라인으로 fib_info 객체 생성
3. fib_create_info() 함수에서 ```ofi = fib_find_info(fi);``` 라인으로 비슷한 fib_info 객체 탐색
4. 비슷한 객체가 만들어지면 새로 만들어진 fib_info 객체는 free_fib_info() 함수로 해제하고 기존의 fib_info 객체의 fib_treeref 카운터를 1 증가시켜서 반환
5. fib_create_info() 함수에서 ```fa = l ? fib_find_alias(&l->leaf, slen, tos, fi->fib_priority, tb->tb_id, false) : NULL;``` 라인으로 기존에 만들어진 fib_alias가 있는지 탐색
6. 기존에 tos와 priority가 같은 fib_alias가 존재한다면 대체하거나 무시한다. (현재 TOS가 0x04인 fib_alias는 없을 테니 해당 루틴은 실행되지 않음)
7. 아니라면 ```new_fa = kmem_cache_alloc(fn_alias_kmem, GFP_KERNEL);``` 라인으로 새로운 fib_alias 할당
8. ```new_fa->fa_info = fi;``` 라인으로 fib_alias가 기존의 fib_info를 가리키도록 지정

## ICMPv4 Redirect 메시지

라우팅 항목의 입력 장치와 출력 장치가 같으면 항목이 suboptimal이 될 수 있다.  
이러한 경우 ICMPv4 Redirect 메시지가 전송된다. ICMPv4 Redirect 메시지의 코드는 다음과 같다.  
* ICMP_REDIR_NET : 네트워크 재지정
* ICMP_REDIR_HOST : 호스트 재지정
* ICMP_REDIR_NETTOS	: TOS에 대한 네트워크 재지정
* ICMP_REDIR_HOSTTOS : TOS에 대한 호스트 재지정

다음 그림은 suboptimal route의 예시를 보여준다.  
![host_redirect](https://github.com/pr0gr4m/pr0gr4m.github.io/blob/master/img/host_redirect.png?raw=true)

위 구성에서 세 대의 장비 모두 같은 서브넷(192.168.2.0/24)에 있고 모두 게이트웨이(192.168.2.1)를 통해 연결되어 있다.  
AMD 서버에서는 ```ip route add 192.168.2.7 via 192.168.2.10``` 명령으로 윈도우 서버를 노트북에 접근하는 게이트웨이로 추가했다.  
AMD 서버에서 노트북에 트래픽을 전송하면 default gateway가 192.168.2.10 이므로 윈도우 서버에 전송된다.  
하지만 구성 상 AMD 서버는 노트북에 직접 트래픽을 전송하는 것이 가능하며, 이 편이 더욱 효율적이다.  
따라서 윈도우 서버에서는 AMD 서버에서 자신에게 전송한 경로가 suboptimal인 것을 감지하고, AMD 서버에 ICMP_REDIR_HOST 코드가 설정된 ICMPv4 Redirect 메시지를 회신한다.  

### ICMPv4 Redirect 메시지 생성

ICMPv4 Redirect 메시지는 suboptimal 경로가 있으면 전송된다. Redirect 메시지의 생성은 두 단계로 수행된다.  
* [__mkroute_input()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/route.c#L1778) 함수 : RTCF_DOREDIRECT 플래그가 설정된다.
* [ip_forward()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/ip_forward.c#L152) 함수 : [ip_rt_send_redirect()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/route.c#L856) 함수를 호출해 실제로 ICMPv4 Redirect 메시지가 전송된다.

__mkroute_input() 함수에서 RTCF_DOREDIRECT 플래그가 설정되려면 다음 조건이 모두 충족돼야 한다.
* 입력 장치와 출력 장치가 같다.
* /proc/sys/net/ipv4/conf/<device name>/sned_redirects 가 설정돼 있다.
* 발신 장치가 shared media이거나 출발지 주소와 다음 홉 게이트웨이 주소가 같은 서브넷에 있다.
```c
	if (out_dev == in_dev && err && IN_DEV_TX_REDIRECTS(out_dev) &&
	    skb->protocol == htons(ETH_P_IP)) {
		__be32 gw;

		gw = nhc->nhc_gw_family == AF_INET ? nhc->nhc_gw.ipv4 : 0;
		if (IN_DEV_SHARED_MEDIA(out_dev) ||
		    inet_addr_onlink(out_dev, saddr, gw))
			IPCB(skb)->flags |= IPSKB_DOREDIRECT;
	}

	rth->dst.input = ip_forward;	
```

ip_forward() 함수에서 ICMPv4 Redirect 메시지 송신하는 코드는 다음과 같다.
```c
	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	if (IPCB(skb)->flags & IPSKB_DOREDIRECT && !opt->srr &&
	    !skb_sec_path(skb))
		ip_rt_send_redirect(skb);
```

ip_rt_send_redirect() 함수에서는 icmp_send() 함수로 실제 ICMPv4 메시지를 송신한다.
```c
	if (!peer) {
		icmp_send(skb, ICMP_REDIRECT, ICMP_REDIR_HOST,
			  rt_nexthop(rt, ip_hdr(skb)->daddr));
		return;
	}
```

네 번째 매개변수인 rt_nexthop()의 결과는 advised gateway 주소이며, 이 전 그림 예시의 경우 192.168.2.7(노트북의 주소)이 될 것이다.

### ICMPv4 Redirect 메시지 수신

ICMPv4 Redirect 메시지 핸들러는 다음과 같이 icmp_redirect() 함수이다.  
```c
	[ICMP_REDIRECT] = {
		.handler = icmp_redirect,
		.error = 1,
	},
```

처리 과정은 다음과 같다.
1. [icmp_redirect()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/icmp.c#L964) 함수에서 icmp_socket_deliver() 함수를 호출한다.
2. [icmp_socket_deliver()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/icmp.c#L815) 함수에서 ICMPv4 프로토콜의 error handler를 호출한다.
3. icmp_protocol 변수에 등록된 err_handler 함수 icmp_err()가 호출된다.
4. [icmp_err()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/icmp.c#L1320) 함수에서 ICMP_REDIRECT 메시지를 ipv4_redirect() 함수로 처리한다.
5. [ipv4_redirect()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/route.c#L1141) 함수에서 [__ip_do_redirect()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/route.c#L720) 함수를 호출하여 처리한다.

__ip_do_redirect() 함수의 정의는 다음과 같다.
```c
static void __ip_do_redirect(struct rtable *rt, struct sk_buff *skb, struct flowi4 *fl4,
			     bool kill_route)
{
	__be32 new_gw = icmp_hdr(skb)->un.gateway;
	__be32 old_gw = ip_hdr(skb)->saddr;
	struct net_device *dev = skb->dev;
	struct in_device *in_dev;
	struct fib_result res;
	struct neighbour *n;
	struct net *net;

	switch (icmp_hdr(skb)->code & 7) {
	case ICMP_REDIR_NET:
	case ICMP_REDIR_NETTOS:
	case ICMP_REDIR_HOST:
	case ICMP_REDIR_HOSTTOS:
		break;

	default:
		return;
	}

	if (rt->rt_gw_family != AF_INET || rt->rt_gw4 != old_gw)
		return;

	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev)
		return;

	net = dev_net(dev);
	if (new_gw == old_gw || !IN_DEV_RX_REDIRECTS(in_dev) ||
	    ipv4_is_multicast(new_gw) || ipv4_is_lbcast(new_gw) ||
	    ipv4_is_zeronet(new_gw))
		goto reject_redirect;

	if (!IN_DEV_SHARED_MEDIA(in_dev)) {
		if (!inet_addr_onlink(in_dev, new_gw, old_gw))
			goto reject_redirect;
		if (IN_DEV_SEC_REDIRECTS(in_dev) && ip_fib_check_default(new_gw, dev))
			goto reject_redirect;
	} else {
		if (inet_addr_type(net, new_gw) != RTN_UNICAST)
			goto reject_redirect;
	}

	n = __ipv4_neigh_lookup(rt->dst.dev, new_gw);
	if (!n)
		n = neigh_create(&arp_tbl, &new_gw, rt->dst.dev);
	if (!IS_ERR(n)) {
		if (!(n->nud_state & NUD_VALID)) {
			neigh_event_send(n, NULL);
		} else {
			if (fib_lookup(net, fl4, &res, 0) == 0) {
				struct fib_nh_common *nhc;

				fib_select_path(net, &res, fl4, skb);
				nhc = FIB_RES_NHC(res);
				update_or_create_fnhe(nhc, fl4->daddr, new_gw,
						0, false,
						jiffies + ip_rt_gc_timeout);
			}
			if (kill_route)
				rt->dst.obsolete = DST_OBSOLETE_KILL;
			call_netevent_notifiers(NETEVENT_NEIGH_UPDATE, n);
		}
		neigh_release(n);
	}
	return;

reject_redirect:
#ifdef CONFIG_IP_ROUTE_VERBOSE
	if (IN_DEV_LOG_MARTIANS(in_dev)) {
		const struct iphdr *iph = (const struct iphdr *) skb->data;
		__be32 daddr = iph->daddr;
		__be32 saddr = iph->saddr;

		net_info_ratelimited("Redirect from %pI4 on %s about %pI4 ignored\n"
				     "  Advised path = %pI4 -> %pI4\n",
				     &old_gw, dev->name, &new_gw,
				     &saddr, &daddr);
	}
#endif
	;
}
```

다양한 검사를 수행한 후, ```n = __ipv4_neigh_lookup(rt->dst.dev, new_gw);``` 라인으로 이웃 서브시스템에서 탐색을 수행한다.  
탐색 키는 ICMPv4 메시지에서 추출한 advised gateway인 new_gw의 주소이다.  
```update_or_create_fnhe(nhc, fl4->daddr, new_gw, 0, false, jiffies + ip_rt_gc_timeout);``` 라인으로 new_gw의 IP 주소를 지정해 fib_nh_exception를 업데이트/생성한다.  

## FIB TRIE

포스트 초기에 fib_lookup() 함수에서 실제 테이블 탐색을 [fib_table_lookup()](https://elixir.bootlin.com/linux/latest/source/net/ipv4/fib_trie.c#L1432) 함수로 수행한다고 했다.  
fib_table_lookup() 함수는 라우팅 항목을 TRIE 구조로 관리한다. 해당 함수의 정의는 다음과 같다.  
```c
/* should be called with rcu_read_lock */
int fib_table_lookup(struct fib_table *tb, const struct flowi4 *flp,
		     struct fib_result *res, int fib_flags)
{
	struct trie *t = (struct trie *) tb->tb_data;
#ifdef CONFIG_IP_FIB_TRIE_STATS
	struct trie_use_stats __percpu *stats = t->stats;
#endif
	const t_key key = ntohl(flp->daddr);
	struct key_vector *n, *pn;
	struct fib_alias *fa;
	unsigned long index;
	t_key cindex;

	pn = t->kv;
	cindex = 0;

	n = get_child_rcu(pn, cindex);
	if (!n) {
		trace_fib_table_lookup(tb->tb_id, flp, NULL, -EAGAIN);
		return -EAGAIN;
	}

#ifdef CONFIG_IP_FIB_TRIE_STATS
	this_cpu_inc(stats->gets);
#endif

	/* Step 1: Travel to the longest prefix match in the trie */
	for (;;) {
		index = get_cindex(key, n);

		/* This bit of code is a bit tricky but it combines multiple
		 * checks into a single check.  The prefix consists of the
		 * prefix plus zeros for the "bits" in the prefix. The index
		 * is the difference between the key and this value.  From
		 * this we can actually derive several pieces of data.
		 *   if (index >= (1ul << bits))
		 *     we have a mismatch in skip bits and failed
		 *   else
		 *     we know the value is cindex
		 *
		 * This check is safe even if bits == KEYLENGTH due to the
		 * fact that we can only allocate a node with 32 bits if a
		 * long is greater than 32 bits.
		 */
		if (index >= (1ul << n->bits))
			break;

		/* we have found a leaf. Prefixes have already been compared */
		if (IS_LEAF(n))
			goto found;

		/* only record pn and cindex if we are going to be chopping
		 * bits later.  Otherwise we are just wasting cycles.
		 */
		if (n->slen > n->pos) {
			pn = n;
			cindex = index;
		}

		n = get_child_rcu(n, index);
		if (unlikely(!n))
			goto backtrace;
	}

	/* Step 2: Sort out leaves and begin backtracing for longest prefix */
	for (;;) {
		/* record the pointer where our next node pointer is stored */
		struct key_vector __rcu **cptr = n->tnode;

		/* This test verifies that none of the bits that differ
		 * between the key and the prefix exist in the region of
		 * the lsb and higher in the prefix.
		 */
		if (unlikely(prefix_mismatch(key, n)) || (n->slen == n->pos))
			goto backtrace;

		/* exit out and process leaf */
		if (unlikely(IS_LEAF(n)))
			break;

		/* Don't bother recording parent info.  Since we are in
		 * prefix match mode we will have to come back to wherever
		 * we started this traversal anyway
		 */

		while ((n = rcu_dereference(*cptr)) == NULL) {
backtrace:
#ifdef CONFIG_IP_FIB_TRIE_STATS
			if (!n)
				this_cpu_inc(stats->null_node_hit);
#endif
			/* If we are at cindex 0 there are no more bits for
			 * us to strip at this level so we must ascend back
			 * up one level to see if there are any more bits to
			 * be stripped there.
			 */
			while (!cindex) {
				t_key pkey = pn->key;

				/* If we don't have a parent then there is
				 * nothing for us to do as we do not have any
				 * further nodes to parse.
				 */
				if (IS_TRIE(pn)) {
					trace_fib_table_lookup(tb->tb_id, flp,
							       NULL, -EAGAIN);
					return -EAGAIN;
				}
#ifdef CONFIG_IP_FIB_TRIE_STATS
				this_cpu_inc(stats->backtrack);
#endif
				/* Get Child's index */
				pn = node_parent_rcu(pn);
				cindex = get_index(pkey, pn);
			}

			/* strip the least significant bit from the cindex */
			cindex &= cindex - 1;

			/* grab pointer for next child node */
			cptr = &pn->tnode[cindex];
		}
	}

found:
	/* this line carries forward the xor from earlier in the function */
	index = key ^ n->key;

	/* Step 3: Process the leaf, if that fails fall back to backtracing */
	hlist_for_each_entry_rcu(fa, &n->leaf, fa_list) {
		struct fib_info *fi = fa->fa_info;
		struct fib_nh_common *nhc;
		int nhsel, err;

		if ((BITS_PER_LONG > KEYLENGTH) || (fa->fa_slen < KEYLENGTH)) {
			if (index >= (1ul << fa->fa_slen))
				continue;
		}
		if (fa->fa_tos && fa->fa_tos != flp->flowi4_tos)
			continue;
		if (fi->fib_dead)
			continue;
		if (fa->fa_info->fib_scope < flp->flowi4_scope)
			continue;
		fib_alias_accessed(fa);
		err = fib_props[fa->fa_type].error;
		if (unlikely(err < 0)) {
out_reject:
#ifdef CONFIG_IP_FIB_TRIE_STATS
			this_cpu_inc(stats->semantic_match_passed);
#endif
			trace_fib_table_lookup(tb->tb_id, flp, NULL, err);
			return err;
		}
		if (fi->fib_flags & RTNH_F_DEAD)
			continue;

		if (unlikely(fi->nh)) {
			if (nexthop_is_blackhole(fi->nh)) {
				err = fib_props[RTN_BLACKHOLE].error;
				goto out_reject;
			}

			nhc = nexthop_get_nhc_lookup(fi->nh, fib_flags, flp,
						     &nhsel);
			if (nhc)
				goto set_result;
			goto miss;
		}

		for (nhsel = 0; nhsel < fib_info_num_path(fi); nhsel++) {
			nhc = fib_info_nhc(fi, nhsel);

			if (!fib_lookup_good_nhc(nhc, fib_flags, flp))
				continue;
set_result:
			if (!(fib_flags & FIB_LOOKUP_NOREF))
				refcount_inc(&fi->fib_clntref);

			res->prefix = htonl(n->key);
			res->prefixlen = KEYLENGTH - fa->fa_slen;
			res->nh_sel = nhsel;
			res->nhc = nhc;
			res->type = fa->fa_type;
			res->scope = fi->fib_scope;
			res->fi = fi;
			res->table = tb;
			res->fa_head = &n->leaf;
#ifdef CONFIG_IP_FIB_TRIE_STATS
			this_cpu_inc(stats->semantic_match_passed);
#endif
			trace_fib_table_lookup(tb->tb_id, flp, nhc, err);

			return err;
		}
	}
miss:
#ifdef CONFIG_IP_FIB_TRIE_STATS
	this_cpu_inc(stats->semantic_match_miss);
#endif
	goto backtrace;
}
```

```found:``` 레이블 이 전 까지는 TRIE node를 탐색하는 과정이다.  
TRIE Leef node를 찾으면, 그에 맞는 fib_alias 리스트를 순회하며 fib_info 객체를 구한다.  
```c
	hlist_for_each_entry_rcu(fa, &n->leaf, fa_list) {
		struct fib_info *fi = fa->fa_info;
```
경로의 tos나 scope 등을 검사한 후, error 코드가 설정되어 있다면 fib_info 파트에서 설명한 바와 같이 error를 처리한다.
```c
		if (unlikely(err < 0)) {
out_reject:
#ifdef CONFIG_IP_FIB_TRIE_STATS
			this_cpu_inc(stats->semantic_match_passed);
#endif
			trace_fib_table_lookup(tb->tb_id, flp, NULL, err);
			return err;
		}
```
적절한 경로를 찾았다면 fib_result에 경로 정보를 저장한다.
```c
		for (nhsel = 0; nhsel < fib_info_num_path(fi); nhsel++) {
			nhc = fib_info_nhc(fi, nhsel);

			if (!fib_lookup_good_nhc(nhc, fib_flags, flp))
				continue;
set_result:
			if (!(fib_flags & FIB_LOOKUP_NOREF))
				refcount_inc(&fi->fib_clntref);

			res->prefix = htonl(n->key);
			res->prefixlen = KEYLENGTH - fa->fa_slen;
			res->nh_sel = nhsel;
			res->nhc = nhc;
			res->type = fa->fa_type;
			res->scope = fi->fib_scope;
			res->fi = fi;
			res->table = tb;
			res->fa_head = &n->leaf;
#ifdef CONFIG_IP_FIB_TRIE_STATS
			this_cpu_inc(stats->semantic_match_passed);
#endif
			trace_fib_table_lookup(tb->tb_id, flp, nhc, err);

			return err;
		}
	}
```