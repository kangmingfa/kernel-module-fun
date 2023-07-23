Kernel module fun
=================

## Motivation

I didn't know at all how kernel modules worked. This is me learning
how. This is all tested using the `4.19.0-9` kernel.

## Contents

**`hello.c`**: a simple "hello world" module

**`who-connect-me.c`**: a custom netfilter hook to log remote address from TCP SYN packet

## Wireshark filter condition
tcp.port eq 8888

## Compiling them

I'm running Linux `4.19.0-9` / `5.4.0-150`. (run `uname -r`) to find out what you're
using. This almost certainly won't work with a `2.x` kernel, and I
don't know enough. It is unlikely to do any lasting damage to your
computer, but I can't guarantee anything.

```
sudo apt-get install linux-headers-$(uname -r)
```

but I don't remember for sure. If you try this out, I'd love to hear.

To compile them, just run

```
make
```

## Inserting into your kernel (at your own risk!)

```
sudo insmod hello.ko
dmesg | tail
```

should display the "hello world" message
