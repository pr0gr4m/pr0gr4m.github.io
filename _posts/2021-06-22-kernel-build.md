---
title: "Linux Kernel Build"
categories: linux kernel
---

해당 포스트는 Ubuntu 20.04 버전을 기준으로 리눅스 커널을 빌드하고 설치하는 방법을 설명합니다.

1. 커널 자동 업데이트 해제
```bash
$ sudo apt-mark hold linux-image-generic linux-headers-generic
$ sudo apt update
```
2. 필요 패키지 설치
```bash
$ sudo apt install vim git make gcc build-essential fakeroot libncurses-dev libncurses5 libncurses5-dev bin86 libssl-dev libelf-dev xz-utils curl wget bc flex bison
```
3. 커널 소스 코드 클론
```bash
$ mkdir git
$ cd git
$ git clone https://github.com/torvalds/linux.git
$ cd linux
```
4. 특정 버전 checkout
```bash
$ git tag
// 현재 어떤 버전의 태그들이 있는지 알 수 있습니다. 파이프라인과 grep을 이용하여 특정 버전들만 볼 수도 있습니다.
$ git checkout -b CV5.9 v5.9
// 커널의 v5.9 tag 소스로 CV5.9 브랜치를 생성하며 체크아웃합니다.
$ git branch
// 현재 브랜치 확인
```
5. 빌드 및 설치
```bash
$ cp /boot/config-현재커널버전 ./.config
// 현재 커널 옵션 파일을 복사해옵니다.
// 우분투 커널 옵션으로 빌드하지 않으면 부팅이 되지 않을 수 있습니다.
$ make menuconfig
// 커널 옵션을 지정해줍니다. 추후 필요에 따라 해당 메뉴에서 재설정 및 재빌드를 할 수도 있습니다.
// Load를 선택하여 복사해온 .config 파일을 로드해줍니다.
// 메뉴 창에서 / 를 치면 검색창이 나옵니다. 검색창에서 옵션을 검색한 후, 해당 번호 숫자를 누르면 바로 옵션을 찾아갑니다.
// CONFIG_SYSTEM_TRUSTED_KEYS="debian/canonical-certs.pem"이 설정되어 빌드가 되지 않는 경우 해당 옵션을 찾아서 지워주시면 됩니다.
$ make -j8
// j 옵션은 병렬 처리 옵션으로, CPU 코어 수 * 1.2 ~ 1.5 정도 주면 됩니다.
// 위의 과정까지는 꼭 일반 유저 권한으로 진행해주셔야 합니다.
$ make modules
// 모듈 빌드
$ sudo make modules_install
// 모듈 빌드 및 설치
$ sudo make install
// 빌드된 커널 설치
$ shutdown -r now
```
6. vim 설정 (.vimrc 파일)

```bash
set hlsearch
set nu
set autoindent
set scrolloff=2
set wildmode=longest,list
set tabstop=8
set softtabstop=8
set cindent
set autowrite
set autoread
set bs=eol,start,indent
set history=256
set laststatus=2
set smartcase
set smarttab
set smartindent
set ruler
set incsearch
set fileencodings=utf-8
set nobackup
set title
set nowrap
set wmnu
set nocompatible
set background=dark

map <F3> <c-w><c-w>
map <F5> :w<cr> :make<cr> :ccl<cr> :cw<cr>

syntax on
colorscheme gruvbox

autocmd FileType * setlocal comments-=://
```
