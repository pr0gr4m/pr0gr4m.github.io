---
title: "Linux Kernel Netfilter"
categories: linux kernel
---

해당 포스트에서는 리눅스 커널의 넷필터에 대해 설명합니다.  
넷필터 서브시스템은 네트워크 스택 내에서 패킷이 이동하는 여러 지점에 콜백을 등록하는 것을 비롯해 주소나 포트 변경, 패킷 drop, 로깅 등과 같이 패킷 상의 다양한 동작을 수행할 수 있는 프레임워크를 제공합니다.  

## 넷필터 프레임워크

넷필터 서브시스템이 수행할 수 있는 기능의 예시는 다음과 같다.  
* 패킷 선택 및 필터링 (iptables)
* 네트워크 주소 변환 (NAT)
* 패킷 맹글링(Mangling; 라우팅 전후로 패킷 헤더의 내용을 수정)
* 연결 추적
* 네트워크 통계 수집

리눅스 커널 넷필터 서브시스템을 기반으로 한 프레임워크 대표 예시는 다음과 같다.  
* iptables : 넷필터에 대한 관리 계층을 제공하는 유저 스페이스 프레임워크로, 넷필터 규칙의 추가와 삭제, 통계 표시, 테이블 추가, 테이블 카운터 초기화 등의 기능이 있다.  
* IPVS : transport 계층의 로드밸런싱 기능(Layer 4 LAN Switching)을 제공하는 IP 가상 서버 솔루션이다.
* IPSet : ipset 유틸리티로 IP 주소, 포트 주소, MAC 주소, 인터페이스 이름 등을 저장할 수 있는 기능을 제공하는 프레임워크다.

## 넷필터 훅

네트워크 스택에는 넷필터 훅을 등록할 수 있는 다섯 개의 지점이 있다.  
다섯 개의 훅의 이름은 다음과 같다.  
* NF_INET_PRE_ROUTING : ```ip_rcv()``` 함수와 ```ipv6_rcv()``` 함수에 있다. 라우팅 서브시스템 탐색을 수행하기 전 모든 수신 패킷이 도착하는 첫 번째 훅 지점이다.
* NF_INET_LOCAL_IN : ```ip_local_deliver()``` 함수와 ```ip6_input()``` 함수에 있다. 로컬 호스트로 향하는 모든 수신 패킷은 라우팅 서브시스템 탐색을 수행한 후 이 훅 지점에 도착한다.
* NF_INET_FORWARD : ```ip_forward()``` 함수와 ```ip6_forward()``` 함수에 있다. 포워딩 되는 모든 패킷은 라우팅 서브시스템 탐색을 수행한 후 이 훅 지점에 도착한다.
* NF_INET_POST_ROUTING : ```ip_output()``` 함수와 ```ip6_finish_output2()``` 함수에 있다. 포워딩되거나 로컬호스트에서 생성되어 전송되는 모든 송신 패킷은 라우팅 서브시스템 탐색을 수행한 후 해당 지점에 도착한다. NF_INET_FORWARD/NF_INET_LOCAl_OUT 보다 후에 도착하는 지점이다.
* NF_INET_LOCAL_OUT : ```__ip_local_out()``` 함수와 ```__ip6_local_out()``` 함수에 있다. 로컬 호스트에서 생성된 모든 송신 패킷이 도착하는 첫 번째 훅 지점이다.

넷필터 훅을 등록하는 매크로 NF_HOOK의 정의는 다음과 같다.  
```c
static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
	if (ret == 1)
		ret = okfn(net, sk, skb);
	return ret;
}

/**
 *	nf_hook - call a netfilter hook
 *
 *	Returns 1 if the hook has allowed the packet to pass.  The function
 *	okfn must be invoked by the caller in this case.  Any other return
 *	value indicates the packet has been consumed by the hook.
 */
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net,
			  struct sock *sk, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	struct nf_hook_entries *hook_head = NULL;
	int ret = 1;

#ifdef CONFIG_JUMP_LABEL
	if (__builtin_constant_p(pf) &&
	    __builtin_constant_p(hook) &&
	    !static_key_false(&nf_hooks_needed[pf][hook]))
		return 1;
#endif

	rcu_read_lock();
	switch (pf) {
	case NFPROTO_IPV4:
		hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]);
		break;
	case NFPROTO_IPV6:
		hook_head = rcu_dereference(net->nf.hooks_ipv6[hook]);
		break;
	case NFPROTO_ARP:
#ifdef CONFIG_NETFILTER_FAMILY_ARP
		if (WARN_ON_ONCE(hook >= ARRAY_SIZE(net->nf.hooks_arp)))
			break;
		hook_head = rcu_dereference(net->nf.hooks_arp[hook]);
#endif
		break;
	case NFPROTO_BRIDGE:
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
		hook_head = rcu_dereference(net->nf.hooks_bridge[hook]);
#endif
		break;
#if IS_ENABLED(CONFIG_DECNET)
	case NFPROTO_DECNET:
		hook_head = rcu_dereference(net->nf.hooks_decnet[hook]);
		break;
#endif
	default:
		WARN_ON_ONCE(1);
		break;
	}

	if (hook_head) {
		struct nf_hook_state state;

		nf_hook_state_init(&state, hook, pf, indev, outdev,
				   sk, net, okfn);

		ret = nf_hook_slow(skb, &state, hook_head, 0);
	}
	rcu_read_unlock();

	return ret;
}
```

NF_HOOK() 매크로의 매개변수는 다음과 같다.  
* pf : 프로토콜 패밀리
* hook : 위에서 언급한 후킹 값 중 하나이다. (NF_INET_PRE_ROUTING 등)
* net : 네트워크 네임스페이스 객체
* sk : 소켓 객체
* skb : 처리 중인 패킷을 나타내는 SKB 객체
* in : 입력 네트워크 장치
* out : 출력 네트워크 장치
* okfn : 훅이 종료되면 호출될 함수 포인터

넷필터 훅의 반환 값은 [다음](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netfilter.h#L11) 중 하나여야 한다.   
* NF_DROP(0) : 패킷을 폐기한다.
* NF_ACCEPT(1) : 패킷이 커널 네트워크 스택에서 계속 이동한다.
* NF_STOLEN : 패킷은 훅 함수로 처리되어 이동하지 않는다.
* NF_QUEUE : 유저 스페이스 큐에 패킷을 넣는다.
* NF_REPEAT : 훅 함수가 다시 호출돼야 한다.

(그 외 NF_STOP 값은 deprecated 되었다.)

### 넷필터 훅 등록

넷필터 훅 콜백을 등록하려면 ```nf_hook_ops``` 객체 혹은 객체 배열을 정의한 후 등록해야 한다. 해당 구조체의 정의는 다음과 같다.  
```c
typedef unsigned int nf_hookfn(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state);

struct nf_hook_ops {
	/* User fills in from here down. */
	nf_hookfn		*hook;
	struct net_device	*dev;
	void			*priv;
	u_int8_t		pf;
	unsigned int		hooknum;
	/* Hooks are ordered in ascending priority. */
	int			priority;
};
```
* hook : 등록하려는 훅 콜백
* pf : 프로토콜 패밀리 (NFPROTO_IPv4 등)
* hooknum : 다섯 가지 넷필터 훅 중 하나 (NF_INET_PRE_ROUTING 등)
* priority : 훅 콜백의 우선순위로, 낮은 훅 콜백이 먼저 호출된다.

넷필터 훅을 등록 및 해제하는 함수는 다음과 같다.  
* ```int nf_register_hook(struct nf_hook_ops *reg);``` : 하나의 넷필터 훅을 ops 객체로 등록한다.
* ```void nf_unregister_hook(struct nf_hook_ops *reg);``` : 등록한 넷필터 훅을 해제한다.
* ```int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n);``` : 여러 개의 넷필터 훅을 ops 객체 배열로 등록한다. 두 번째 매개변수는 배열의 요소 개수이다.
* ```void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n);``` : 여러 개의 등록된 넷필터 훅을 해제한다. 두 번째 매개변수는 배열의 요소 개수이다.

## Connection Tracking

FTP 또는 SIP와 같은 세션 기반 트래픽을 고려하여 커널은 연결 추적 기능을 제공한다.  
연결 추적 계층의 주요 목적은 NAT의 기반 역할을 하는 것이다.  

### Connection Tracking 초기화

IPv4의 연결 추적 초기화를 위한 ```nf_hook_ops``` 객체의 배열은 다음과 같이 정의되어 있다.  
```c
/* Connection tracking may drop packets, but never alters them, so
   make it the first hook. */
static struct nf_hook_ops ipv4_conntrack_ops[] __read_mostly = {
	{
		.hook		= ipv4_conntrack_in,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK,
	},
	{
		.hook		= ipv4_conntrack_local,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_CONNTRACK,
	},
	{
		.hook		= ipv4_helper,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		.hook		= ipv4_confirm,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
	},
	{
		.hook		= ipv4_helper,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_CONNTRACK_HELPER,
	},
	{
		.hook		= ipv4_confirm,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM,
	},
};
```
주요 후킹 함수는 NF_INET_PRE_ROUTING 후킹에서 처리되는 ```ipv4_conntrack_in()``` 함수와 NF_INET_LOCAL_OUT 후킹에서 처리되는 ```ipv4_conntrack_local()``` 함수이다.  
위 두 함수의 우선순위 NF_IP_PRI_CONNTRACK(-200)는 다른 우선순위 NF_IP_PRI_CONNTRACK_HELPER(300)와 NF_IP_PRI_CONNTRACK_CONFIRM(INT_MAX)보다 높다.  
또한, 두 함수의 정의를 살펴보면 결국 ```nf_conntrack_in()``` 함수에 상응하는 hooknum을 전달하여 호출한다.  
이러한 연결 추적 후킹 오퍼레이션 객체는 [nf_conntrack_l3proto_ipv4_init()](https://elixir.bootlin.com/linux/v4.3/source/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c#L451) 함수에서 등록한다.  
다음 그림은 등록된 훅 지점에 따른 연결 추적 콜백 함수의 flow를 보여준다.  
![conn_track](https://github.com/pr0gr4m/pr0gr4m.github.io/blob/master/img/conn_track.png?raw=true)

### 연결 추적 항목



## IPTables

## NAT