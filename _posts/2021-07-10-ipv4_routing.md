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

fib_lookup() 함수는 fib_get_table() 함수로 Main FIB 테이블을 가져와 fib_table_lookup() 함수로 탐색을 수행한다.  
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

